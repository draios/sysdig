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

#ifdef CYGWING_AGENT
	matches = matches || resolve_container_impl<sinsp_container_engine_docker>(tinfo, query_os_for_missing_info);

#else
	matches = matches || resolve_container_impl<
		libsinsp::container_engine::docker,
#if defined(HAS_CAPTURE)
		libsinsp::container_engine::cri,
#endif
		libsinsp::container_engine::lxc,
		libsinsp::container_engine::libvirt_lxc,
		libsinsp::container_engine::mesos,
		libsinsp::container_engine::rkt
	>(tinfo, query_os_for_missing_info);

#endif // CYGWING_AGENT

	// Also identify if this thread is part of a container healthcheck
	identify_healthcheck(tinfo);

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

	if(!container_info.m_mesos_task_id.empty())
	{
		container["mesos_task_id"] = container_info.m_mesos_task_id;
	}
	return Json::FastWriter().write(obj);
}

bool sinsp_container_manager::container_to_sinsp_event(const string& json, sinsp_evt* evt, int64_t tid)
{
	// TODO: variable event length
	size_t evt_len = SP_EVT_BUF_SIZE;
	size_t totlen = sizeof(scap_evt) +  sizeof(uint16_t) + json.length() + 1;

	if(totlen > evt_len)
	{
		ASSERT(false);
		return false;
	}

	evt->m_cpuid = 0;
	evt->m_evtnum = 0;
	evt->m_inspector = m_inspector;

	scap_evt* scapevt = evt->m_pevt;

	scapevt->ts = m_inspector->m_lastevent_ts;
	scapevt->tid = tid;
	scapevt->len = (uint32_t)totlen;
	scapevt->type = PPME_CONTAINER_JSON_E;
	scapevt->nparams = 1;

	uint16_t* lens = (uint16_t*)((char *)scapevt + sizeof(struct ppm_evt_hdr));
	char* valptr = (char*)lens + sizeof(uint16_t);

	*lens = (uint16_t)json.length() + 1;
	memcpy(valptr, json.c_str(), *lens);

	evt->init();
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

void sinsp_container_manager::notify_new_container(const sinsp_container_info& container_info, int64_t tid)
{
	sinsp_evt *evt = new sinsp_evt();
	evt->m_pevt_storage = new char[SP_EVT_BUF_SIZE];
	evt->m_pevt = (scap_evt *) evt->m_pevt_storage;

	if(container_to_sinsp_event(container_to_json(container_info), evt, tid))
	{
		std::shared_ptr<sinsp_evt> cevt(evt);

		// Enqueue it onto the queue of pending container events for the inspector
		m_inspector->m_pending_container_evts.push(cevt);
	}
	else
	{
		delete evt;
	}
}

void sinsp_container_manager::dump_containers(scap_dumper_t* dumper)
{
	for(unordered_map<string, sinsp_container_info>::const_iterator it = m_containers.begin(); it != m_containers.end(); ++it)
	{
		if(container_to_sinsp_event(container_to_json(it->second), &m_inspector->m_meta_evt))
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

void sinsp_container_manager::cleanup()
{
	libsinsp::container_engine::docker::cleanup();
#if defined(HAS_CAPTURE)
	libsinsp::container_engine::cri::cleanup();
#endif
}

void sinsp_container_manager::set_query_docker_image_info(bool query_image_info)
{
	libsinsp::container_engine::docker::set_query_image_info(query_image_info);
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