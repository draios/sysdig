/*
Copyright (C) 2013-2018 Draios Inc dba Sysdig.

This file is part of sysdig.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#include "zlib.h"

#include "container_engine/cri.h"
#include "container_engine/docker.h"
#include "container_engine/rkt.h"
#include "container_engine/libvirt_lxc.h"
#include "container_engine/lxc.h"
#include "container_engine/mesos.h"

#include "sinsp.h"
#include "sinsp_int.h"
#include "container.h"
#include "utils.h"

using namespace libsinsp;

sinsp_container_manager::sinsp_container_manager(sinsp* inspector) :
	m_inspector(inspector),
	m_last_flush_time_ns(0)
{
}

sinsp_container_manager::~sinsp_container_manager()
{
}

bool sinsp_container_manager::remove_inactive_containers()
{
	bool res = false;

	if(m_last_flush_time_ns == 0)
	{
		m_last_flush_time_ns = m_inspector->m_lastevent_ts - m_inspector->m_inactive_container_scan_time_ns + 30 * ONE_SECOND_IN_NS;
	}

	if(m_inspector->m_lastevent_ts >
		m_last_flush_time_ns + m_inspector->m_inactive_container_scan_time_ns)
	{
		res = true;

		m_last_flush_time_ns = m_inspector->m_lastevent_ts;

		g_logger.format(sinsp_logger::SEV_INFO, "Flushing container table");

		set<string> containers_in_use;

		threadinfo_map_t* threadtable = m_inspector->m_thread_manager->get_threads();

		threadtable->loop([&] (const sinsp_threadinfo& tinfo) {
			if(!tinfo.m_container_id.empty())
			{
				containers_in_use.insert(tinfo.m_container_id);
			}
			return true;
		});

		for(unordered_map<string, sinsp_container_info>::iterator it = m_containers.begin(); it != m_containers.end();)
		{
			if(containers_in_use.find(it->first) == containers_in_use.end())
			{
				for(const auto &remove_cb : m_remove_callbacks)
				{
					remove_cb(m_containers[it->first]);
				}
				m_containers.erase(it++);
			}
			else
			{
				++it;
			}
		}
	}

	return res;
}

sinsp_container_info* sinsp_container_manager::get_container(const string& container_id)
{
	auto it = m_containers.find(container_id);
	if(it != m_containers.end())
	{
		return &it->second;
	}

	return nullptr;
}

bool sinsp_container_manager::resolve_container(sinsp_threadinfo* tinfo, bool query_os_for_missing_info)
{
	ASSERT(tinfo);
	bool matches = false;

	tinfo->m_container_id = "";
	if (m_inspector->m_parser->m_fd_listener)
	{
		matches = m_inspector->m_parser->m_fd_listener->on_resolve_container(this, tinfo, query_os_for_missing_info);
	}

	// Delayed so there's a chance to set alternate socket paths,
	// timeouts, after creation but before inspector open.
	if(m_container_engines.size() == 0)
	{
		create_engines();
	}

	for(auto &eng : m_container_engines)
	{
		matches = matches || eng->resolve(this, tinfo, query_os_for_missing_info);

		if(matches)
		{
			break;
		}
	}

	// Also identify if this thread is part of a container healthcheck
	identify_healthcheck(tinfo);

	return matches;
}

size_t sinsp_container_manager::container_json_evt_len(size_t json_size)
{
	return sizeof(scap_evt) +  sizeof(uint16_t) + json_size + 1;
}

bool sinsp_container_manager::serialize_json_fits_in_event(size_t size)
{
	return (container_json_evt_len(size) <= SP_EVT_BUF_SIZE);
}

void sinsp_container_manager::serialize_container_json(const Json::Value &obj, std::string &json)
{
	json = Json::FastWriter().write(obj);

	g_logger.format(sinsp_logger::SEV_DEBUG,
			"serialize_container_json: serialized json size %d", json.length());

	// Only compress if enabled and if the data wouldn't fit in an event
	if(m_inspector->get_compress_container_json() &&
	   !serialize_json_fits_in_event(json.length()))
	{
		compress_json_hdr hdr;
		hdr.m_magic = htonl(sinsp_container_manager::s_compress_json_magic);
		hdr.m_uncompress_len = htonl(json.length());

		uLong clen = compressBound(json.length());
		uLong dlen;

		g_logger.format(sinsp_logger::SEV_DEBUG,
				"serialize_container_json: compressing to size %u", clen);

		Bytef *dest = new Bytef[clen];

		int res = compress2(dest, &dlen, (const Bytef *) json.data(), json.size(), Z_DEFAULT_COMPRESSION);

		if(res != Z_OK)
		{
			g_logger.format(sinsp_logger::SEV_WARNING,
					"serialize_container_json: Could not compress buffer (error %d)", res);
		}
		else
		{
			json.assign((char *) &hdr, sizeof(hdr));
			json.append((char *) dest, dlen);
		}

		delete(dest);
	}
}

// If compressed, decompress the provided string
uint32_t sinsp_container_manager::s_compress_json_magic = 0xfeadaceb;

bool sinsp_container_manager::deserialize_container_json(const std::string &json, Json::Value &obj)
{
	// Note: decompression isn't controlled by the flag
	if(json.length() <= sizeof(compress_json_hdr))
	{
		return Json::Reader().parse(json, obj);
	}

	// See if the buffer is compressed
	struct compress_json_hdr *hdr = (struct compress_json_hdr *) json.data();

	if(ntohl(hdr->m_magic) != s_compress_json_magic)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"deserialize_container_json: Container json buffer \"%s\" not compressed, simply parsing", json.c_str());
		return Json::Reader().parse(json, obj);
	}

	g_logger.format(sinsp_logger::SEV_DEBUG,
			"deserialize_container_json: Container json buffer compressed, decompressing first");

	size_t buf_len = ntohl(hdr->m_uncompress_len);
	char *buf = new char[buf_len];

	if(uncompress((Bytef *) buf,
		       &buf_len,
		       (Bytef *) (json.data() + sizeof(struct compress_json_hdr)),
		       json.length() - sizeof(compress_json_hdr)) != Z_OK)
	{
		return false;
	}

	bool ret = Json::Reader().parse(buf, buf + buf_len, obj);

	delete buf;
	return ret;
}

void sinsp_container_manager::trim_container_json(Json::Value &obj, trim_level level)
{
	g_logger.format(sinsp_logger::SEV_DEBUG,
			"trim_container_json: trimming at level %d",
			(int) level);

	Json::Value &cobj = obj["container"];
	switch(level)
	{
	case LEVEL_SOME_LABELS:
	{
		// Try dropping the following labels:

		// - "url"
		// - "summary"
		// - "vcs-type"
		// - "vcs-ref"
		// - "description"
		// - "io.k8s.description"

		if(cobj.isMember("labels"))
		{
			Json::Value &labels = cobj["labels"];

			labels.removeMember("url");
			labels.removeMember("summary");
			labels.removeMember("vcs-type");
			labels.removeMember("vcs-ref");
			labels.removeMember("description");
			labels.removeMember("io.k8s.description");
		}

		// Any Mounts with a Source prefix of
		// "/var/lib/origin/openshift..."
		if(cobj.isMember("Mounts"))
		{
			Json::Value &oldmounts = cobj["Mounts"];
			Json::Value newmounts = Json::Value(Json::arrayValue);

			if(oldmounts.isArray())
			{
				for(uint32_t i=0; i<oldmounts.size(); i++)
				{
					const Json::Value &mount = oldmounts[i];

					if(mount.isMember("Source") &&
					   mount["Source"].isConvertibleTo(Json::stringValue) &&
					   mount["Source"].asString().find("/var/lib/origin/openshift") != 0)
					{
						newmounts.append(mount);
					}
				}

				cobj["Mounts"] = newmounts;
			}
		}

		break;
	}
	case LEVEL_ALL_LABELS:
	{
		// Remove all labels
		cobj.removeMember("labels");

		break;
	}

	case LEVEL_MIN_INFO:
	{
		// only keep name, type, "image*", id, Healthcheck
		Json::Value newobj;

		std::list<const char *> props = {"name", "type", "imagetag", "imagerepo", "imageid", "imagedigest", "image", "id", "Healthcheck"};

		for(auto &prop : props)
		{
			if(cobj.isMember(prop))
			{
				newobj[prop] = obj[prop];
			}
		}

		obj["container"] = newobj;

		break;
	}

	case LEVEL_END:
	default:
		break;
	}
}

string sinsp_container_manager::container_to_json(const sinsp_container_info& container_info)
{
	Json::Value obj;
	std::string json;

	Json::Value& container = obj["container"];
	container["id"] = container_info.m_id;
	container["type"] = container_info.m_type;
	container["name"] = container_info.m_name;
	container["image"] = container_info.m_image;
	container["imageid"] = container_info.m_imageid;
	container["imagerepo"] = container_info.m_imagerepo;
	container["imagetag"] = container_info.m_imagetag;
	container["imagedigest"] = container_info.m_imagedigest;
	container["privileged"] = container_info.m_privileged;
	container["is_pod_sandbox"] = container_info.m_is_pod_sandbox;

	Json::Value mounts = Json::arrayValue;

	for (auto &mntinfo : container_info.m_mounts)
	{
		Json::Value mount;

		mount["Source"] = mntinfo.m_source;
		mount["Destination"] = mntinfo.m_dest;
		mount["Mode"] = mntinfo.m_mode;
		mount["RW"] = mntinfo.m_rdwr;
		mount["Propagation"] = mntinfo.m_propagation;

		mounts.append(mount);
	}

	container["Mounts"] = mounts;

	if(!container_info.m_healthcheck_obj.isNull())
	{
		container["Healthcheck"] = container_info.m_healthcheck_obj;
	}

	char addrbuff[100];
	uint32_t iph = htonl(container_info.m_container_ip);
	inet_ntop(AF_INET, &iph, addrbuff, sizeof(addrbuff));
	container["ip"] = addrbuff;

	Json::Value port_mappings = Json::arrayValue;

	for(auto &mapping : container_info.m_port_mappings)
	{
		Json::Value jmap;
		jmap["HostIp"] = mapping.m_host_ip;
		jmap["HostPort"] = mapping.m_host_port;
		jmap["ContainerPort"] = mapping.m_container_port;

		port_mappings.append(jmap);
	}

	container["port_mappings"] = port_mappings;

	Json::Value labels;
	for (auto &pair : container_info.m_labels)
	{
		labels[pair.first] = pair.second;
	}
	container["labels"] = labels;

	Json::Value env_vars = Json::arrayValue;

	for (auto &var : container_info.m_env)
	{
		// Only append a limited set of mesos/marathon-related
		// environment variables.
		if(var.find("MESOS") != std::string::npos ||
		   var.find("MARATHON") != std::string::npos ||
		   var.find("mesos") != std::string::npos)
		{
			env_vars.append(var);
		}
	}
	container["env"] = env_vars;

	container["memory_limit"] = (Json::Value::Int64) container_info.m_memory_limit;
	container["swap_limit"] = (Json::Value::Int64) container_info.m_swap_limit;
	container["cpu_shares"] = (Json::Value::Int64) container_info.m_cpu_shares;
	container["cpu_quota"] = (Json::Value::Int64) container_info.m_cpu_quota;
	container["cpu_period"] = (Json::Value::Int64) container_info.m_cpu_period;

	if(!container_info.m_mesos_task_id.empty())
	{
		container["mesos_task_id"] = container_info.m_mesos_task_id;
	}

	container["metadata_deadline"] = (Json::Value::UInt64) container_info.m_metadata_deadline;

	serialize_container_json(obj, json);

	// Ensure that the json representation will fit in a ~4k event.
	if(m_inspector->get_trim_container_json())
	{
		for(int level = LEVEL_SOME_LABELS;
		    (level != LEVEL_END &&
		     !serialize_json_fits_in_event(json.length()));
		    level++)
		{
			trim_container_json(obj, (trim_level) level);
			serialize_container_json(obj, json);
		}

		// There's a very very rare possibility that even
		// after applying all levels, the resulting event is
		// still too large. That will be noted in
		// container_to_sinsp_event.
	}

	return json;
}

bool sinsp_container_manager::container_to_sinsp_event(const string& json, sinsp_evt* evt, shared_ptr<sinsp_threadinfo> tinfo)
{
	// TODO: variable event length
	size_t evt_len = SP_EVT_BUF_SIZE;
	size_t totlen = container_json_evt_len(json.length());

	if(!serialize_json_fits_in_event(json.length()))
	{
		g_logger.format(sinsp_logger::SEV_ERROR,
				"container_to_sinsp_event: event len %d > max len %d w/ json \"%s\", returning false",
				totlen, evt_len, json.c_str());
		ASSERT(false);
		return false;
	}

	evt->m_cpuid = 0;
	evt->m_evtnum = 0;
	evt->m_inspector = m_inspector;

	scap_evt* scapevt = evt->m_pevt;

	if(m_inspector->m_lastevent_ts == 0)
	{
		// This can happen at startup when containers are
		// being created as a part of the initial process
		// scan.
		scapevt->ts = sinsp_utils::get_current_time_ns();
	}
	else
	{
		scapevt->ts = m_inspector->m_lastevent_ts;
	}
	scapevt->tid = -1;
	scapevt->len = (uint32_t)totlen;
	scapevt->type = PPME_CONTAINER_JSON_E;
	scapevt->nparams = 1;

	uint16_t* lens = (uint16_t*)((char *)scapevt + sizeof(struct ppm_evt_hdr));
	char* valptr = (char*)lens + sizeof(uint16_t);

	*lens = (uint16_t)json.length() + 1;
	memcpy(valptr, json.c_str(), *lens);

	evt->init();
	evt->m_tinfo_ref = tinfo;
	evt->m_tinfo = tinfo.get();

	return true;
}

const unordered_map<string, sinsp_container_info>* sinsp_container_manager::get_containers()
{
	return &m_containers;
}

void sinsp_container_manager::add_container(const sinsp_container_info& container_info, sinsp_threadinfo *thread_info)
{
	m_containers[container_info.m_id] = container_info;

	for(const auto &new_cb : m_new_callbacks)
	{
		new_cb(m_containers[container_info.m_id], thread_info);
	}
}

void sinsp_container_manager::notify_new_container(const sinsp_container_info& container_info)
{
	sinsp_evt *evt = new sinsp_evt();
	evt->m_pevt_storage = new char[SP_EVT_BUF_SIZE];
	evt->m_pevt = (scap_evt *) evt->m_pevt_storage;

	if(container_to_sinsp_event(container_to_json(container_info), evt, container_info.get_tinfo(m_inspector)))
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"notify_new_container (%s): created CONTAINER_JSON event, queuing to inspector",
				container_info.m_id.c_str());

		std::shared_ptr<sinsp_evt> cevt(evt);

		// Enqueue it onto the queue of pending container events for the inspector
		m_inspector->m_pending_container_evts.push(cevt);
	}
	else
	{
		g_logger.format(sinsp_logger::SEV_ERROR,
				"notify_new_container (%s): could not create CONTAINER_JSON event, dropping",
				container_info.m_id.c_str());
		delete evt;
	}
}

void sinsp_container_manager::dump_containers(scap_dumper_t* dumper)
{
	for(unordered_map<string, sinsp_container_info>::const_iterator it = m_containers.begin(); it != m_containers.end(); ++it)
	{
		if(container_to_sinsp_event(container_to_json(it->second), &m_inspector->m_meta_evt, it->second.get_tinfo(m_inspector)))
		{
			int32_t res = scap_dump(m_inspector->m_h, dumper, m_inspector->m_meta_evt.m_pevt, m_inspector->m_meta_evt.m_cpuid, 0);
			if(res != SCAP_SUCCESS)
			{
				throw sinsp_exception(scap_getlasterr(m_inspector->m_h));
			}
		}
	}
}

string sinsp_container_manager::get_container_name(sinsp_threadinfo* tinfo)
{
	string res;

	if(tinfo->m_container_id.empty())
	{
		res = "host";
	}
	else
	{
		const sinsp_container_info *container_info = get_container(tinfo->m_container_id);

		if(!container_info)
		{
			return NULL;
		}

		if(container_info->m_name.empty())
		{
			return NULL;
		}

		res = container_info->m_name;
	}

	return res;
}

void sinsp_container_manager::identify_healthcheck(sinsp_threadinfo *tinfo)
{
	// This thread is a part of a container healthcheck if its
	// parent thread is part of a health check.
	sinsp_threadinfo* ptinfo = tinfo->get_parent_thread();

	if(ptinfo && ptinfo->m_is_container_healthcheck)
	{
		tinfo->m_is_container_healthcheck = true;
		return;
	}

	sinsp_container_info *cinfo = get_container(tinfo->m_container_id);

	if(!cinfo)
	{
		return;
	}

	// Otherwise, the thread is a part of a container healthcheck if:
	//
	// 1. the comm and args match the container's healthcheck
	// 2. we traverse the parent state and do *not* find vpid=1,
	//    or find a process not in a container
	//
	// This indicates the initial process of the healthcheck.

	if(!cinfo->m_has_healthcheck ||
	   cinfo->m_healthcheck_exe != tinfo->m_exe ||
	   cinfo->m_healthcheck_args != tinfo->m_args)
	{
		return;
	}

	if(tinfo->m_vpid == 1)
	{
		return;
	}

	bool found_container_init = false;
	sinsp_threadinfo::visitor_func_t visitor =
		[&found_container_init] (sinsp_threadinfo *ptinfo)
	{
		if(ptinfo->m_vpid == 1 && !ptinfo->m_container_id.empty())
		{
			found_container_init = true;

			return false;
		}

		return true;
	};

	tinfo->traverse_parent_state(visitor);

	if(!found_container_init)
	{
		tinfo->m_is_container_healthcheck = true;
	}
}

void sinsp_container_manager::subscribe_on_new_container(new_container_cb callback)
{
	m_new_callbacks.emplace_back(callback);
}

void sinsp_container_manager::subscribe_on_remove_container(remove_container_cb callback)
{
	m_remove_callbacks.emplace_back(callback);
}

void sinsp_container_manager::create_engines()
{
	m_container_engines.emplace_back(new container_engine::docker());
#ifndef CYGWING_AGENT
#if defined(HAS_CAPTURE)
	m_container_engines.emplace_back(new container_engine::cri());
#endif
	m_container_engines.emplace_back(new container_engine::lxc());
	m_container_engines.emplace_back(new container_engine::libvirt_lxc());
	m_container_engines.emplace_back(new container_engine::mesos());
	m_container_engines.emplace_back(new container_engine::rkt());
#endif
}

void sinsp_container_manager::cleanup()
{
	for(auto &eng : m_container_engines)
	{
		eng->cleanup();
	}
}

void sinsp_container_manager::set_query_docker_image_info(bool query_image_info)
{
	libsinsp::container_engine::docker_async_source::set_query_image_info(query_image_info);
}

void sinsp_container_manager::set_cri_extra_queries(bool extra_queries)
{
#if defined(HAS_CAPTURE)
	libsinsp::container_engine::cri::set_extra_queries(extra_queries);
#endif
}

void sinsp_container_manager::set_cri_socket_path(const std::string &path)
{
#if defined(HAS_CAPTURE)
	libsinsp::container_engine::cri::set_cri_socket_path(path);
#endif
}

void sinsp_container_manager::set_cri_timeout(int64_t timeout_ms)
{
#if defined(HAS_CAPTURE)
	libsinsp::container_engine::cri::set_cri_timeout(timeout_ms);
#endif
}
