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

#include <algorithm>

#include "container_engine/cri.h"
#include "container_engine/docker.h"
#include "container_engine/rkt.h"
#include "container_engine/libvirt_lxc.h"
#include "container_engine/lxc.h"
#include "container_engine/mesos.h"
#include "container_engine/bpm.h"

#include "sinsp.h"
#include "sinsp_int.h"
#include "container.h"
#include "utils.h"

using namespace libsinsp;

std::string sinsp_container_manager::s_incomplete_info_name = "incomplete";

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

		auto containers = m_containers.lock();
		for(auto it = containers->begin(); it != containers->end();)
		{
			if(containers_in_use.find(it->first) == containers_in_use.end())
			{
				for(const auto &remove_cb : m_remove_callbacks)
				{
					remove_cb((*containers)[it->first]);
				}
				containers->erase(it++);
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
	auto containers = m_containers.lock();
	auto it = containers->find(container_id);
	if(it != containers->end())
	{
		return &it->second;
	}

	return nullptr;
}

sinsp_container_info* sinsp_container_manager::get_or_create_container(
	sinsp_container_type type, const string& id, const std::string& name, sinsp_threadinfo* tinfo)
{
	auto containers = m_containers.lock();
	auto it = containers->find(id);
	if(it != containers->end())
	{
		return &it->second;
	}

	// Add a minimal container_info object where only the
	// container id, (possibly) name, and a container
	// image = incomplete is filled in. This may be
	// overridden later once async lookup completes.
	sinsp_container_info container_info;

	g_logger.format(sinsp_logger::SEV_DEBUG,
			"container_manager (%s): No existing container info, creating initial stub info with type=%d",
			id.c_str(), type);

	container_info.m_type = type;
	container_info.m_id = id;
	container_info.m_name = name.empty() ? s_incomplete_info_name : name;
	container_info.m_image = s_incomplete_info_name;
	container_info.m_imageid = s_incomplete_info_name;
	container_info.m_imagerepo = s_incomplete_info_name;
	container_info.m_imagetag = s_incomplete_info_name;
	container_info.m_imagedigest = s_incomplete_info_name;
	container_info.m_metadata_complete = false;
	container_info.m_successful = false;

	add_container(container_info, tinfo, containers);
	return &(*containers)[id];
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

	// Also possibly set the category for the threadinfo
	identify_category(tinfo);

	return matches;
}

string sinsp_container_manager::container_to_json(const sinsp_container_info& container_info)
{
	Json::Value obj;
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

	sinsp_container_info::container_health_probe::add_health_probes(container_info.m_health_probes, container);

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
	return Json::FastWriter().write(obj);
}

bool sinsp_container_manager::container_to_sinsp_event(const string& json, sinsp_evt* evt, shared_ptr<sinsp_threadinfo> tinfo)
{
	size_t totlen = sizeof(scap_evt) +  sizeof(uint16_t) + json.length() + 1;

	ASSERT(evt->m_pevt_storage == nullptr);
	evt->m_pevt_storage = new char[totlen];
	evt->m_pevt = (scap_evt *) evt->m_pevt_storage;

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

ConstMutexGuard<unordered_map<string, sinsp_container_info>> sinsp_container_manager::get_containers()
{
	return m_containers.lock();
}

void sinsp_container_manager::add_container(const sinsp_container_info& container_info, sinsp_threadinfo *thread_info)
{
	auto containers = m_containers.lock();
	add_container(container_info, thread_info, containers);
}

void sinsp_container_manager::add_container(const sinsp_container_info& container_info, sinsp_threadinfo *thread_info,
	libsinsp::MutexGuard<std::unordered_map<std::string, sinsp_container_info>>& containers)
{
	(*containers)[container_info.m_id] = container_info;

	for(const auto &new_cb : m_new_callbacks)
	{
		new_cb((*containers)[container_info.m_id], thread_info);
	}
}

bool sinsp_container_manager::update_container(const sinsp_container_info& container_info)
{
	auto containers = m_containers.lock();
	auto it = containers->find(container_info.m_id);
	if(it == containers->end() ||
		(container_info.m_metadata_complete && !it->second.m_successful))
	{
		auto thread_info = container_info.get_tinfo(m_inspector);
		add_container(container_info, thread_info.get(), containers);
		return true;
	}
	else
	{
		return false;
	}
}

void sinsp_container_manager::notify_new_container(const sinsp_container_info& container_info)
{
	sinsp_evt *evt = new sinsp_evt();

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
	for(const auto& it : (*m_containers.lock()))
	{
		sinsp_evt evt;
		if(container_to_sinsp_event(container_to_json(it.second), &evt, it.second.get_tinfo(m_inspector)))
		{
			int32_t res = scap_dump(m_inspector->m_h, dumper, evt.m_pevt, evt.m_cpuid, 0);
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

void sinsp_container_manager::identify_category(sinsp_threadinfo *tinfo)
{
	if(tinfo->m_container_id.empty())
	{
		return;
	}

	sinsp_container_info *cinfo = get_container(tinfo->m_container_id);

	if(!cinfo)
	{
		return;
	}

	if(tinfo->m_vpid == 1)
	{
		if(g_logger.get_severity() >= sinsp_logger::SEV_DEBUG)
		{
			g_logger.format(sinsp_logger::SEV_DEBUG,
					"identify_category (%ld) (%s): initial process for container, assigning CAT_CONTAINER",
					tinfo->m_tid, tinfo->m_comm.c_str());
		}

		tinfo->m_category = sinsp_threadinfo::CAT_CONTAINER;

		return;
	}

	// Categories are passed from parent to child threads
	sinsp_threadinfo* ptinfo = tinfo->get_parent_thread();

	if(ptinfo && ptinfo->m_category != sinsp_threadinfo::CAT_NONE)
	{
		if(g_logger.get_severity() >= sinsp_logger::SEV_DEBUG)
		{
			g_logger.format(sinsp_logger::SEV_DEBUG,
					"identify_category (%ld) (%s): taking parent category %d",
					tinfo->m_tid, tinfo->m_comm.c_str(), ptinfo->m_category);
		}

		tinfo->m_category = ptinfo->m_category;
		return;
	}

	if(!cinfo->m_metadata_complete)
	{
		if(g_logger.get_severity() >= sinsp_logger::SEV_DEBUG)
		{
			g_logger.format(sinsp_logger::SEV_DEBUG,
					"identify_category (%ld) (%s): container metadata incomplete",
					tinfo->m_tid, tinfo->m_comm.c_str());
		}

		return;
	}

	// Otherwise, the thread is a part of a container health probe if:
	//
	// 1. the comm and args match one of the container's health probes
	// 2. we traverse the parent state and do *not* find vpid=1,
	//    or find a process not in a container
	//
	// This indicates the initial process of the health probe.

	sinsp_container_info::container_health_probe::probe_type ptype =
		cinfo->match_health_probe(tinfo);

	if(ptype == sinsp_container_info::container_health_probe::PT_NONE)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"identify_category (%ld) (%s): container health probe PT_NONE",
				tinfo->m_tid, tinfo->m_comm.c_str());

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
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"identify_category (%ld) (%s): not under container init, assigning category %s",
				tinfo->m_tid, tinfo->m_comm.c_str(),
				sinsp_container_info::container_health_probe::probe_type_names[ptype].c_str());

		// Each health probe type maps to a command category
		switch(ptype)
		{
		case sinsp_container_info::container_health_probe::PT_NONE:
		case sinsp_container_info::container_health_probe::PT_END:
			break;
		case sinsp_container_info::container_health_probe::PT_HEALTHCHECK:
			tinfo->m_category = sinsp_threadinfo::CAT_HEALTHCHECK;
			break;
		case sinsp_container_info::container_health_probe::PT_LIVENESS_PROBE:
			tinfo->m_category = sinsp_threadinfo::CAT_LIVENESS_PROBE;
			break;
		case sinsp_container_info::container_health_probe::PT_READINESS_PROBE:
			tinfo->m_category = sinsp_threadinfo::CAT_READINESS_PROBE;
			break;
		}
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
	m_container_engines.emplace_back(new container_engine::bpm());
#endif
}

void sinsp_container_manager::cleanup()
{
	for(auto &eng : m_container_engines)
	{
		eng->cleanup();
	}
}

void sinsp_container_manager::set_docker_socket_path(std::string socket_path)
{
#if defined(HAS_CAPTURE)
	libsinsp::container_engine::docker::set_docker_sock(std::move(socket_path));
#endif
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

void sinsp_container_manager::set_cri_async(bool async)
{
#if defined(HAS_CAPTURE)
	libsinsp::container_engine::cri::set_async(async);
#endif
}

void sinsp_container_manager::set_cri_async_limits(bool async_limits)
{
#if defined(HAS_CAPTURE)
	libsinsp::container_engine::cri::set_async_limits(async_limits);
#endif
}
