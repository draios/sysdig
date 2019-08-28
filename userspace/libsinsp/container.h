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

#pragma once

#include <functional>
#include <memory>

#include "scap.h"

#include "event.h"
#include "container_info.h"

#if !defined(_WIN32) && !defined(CYGWING_AGENT) && defined(HAS_CAPTURE)
#include <curl/curl.h>
#include <curl/easy.h>
#include <curl/multi.h>
#endif

#include "container_engine/container_engine.h"

class sinsp_container_manager
{
public:
	using map_ptr_t = const std::unordered_map<std::string, sinsp_container_info>*;
	using entry_ptr_t = sinsp_container_info*;

	sinsp_container_manager(sinsp* inspector);
	virtual ~sinsp_container_manager();

	map_ptr_t get_containers();
	bool remove_inactive_containers();
	void add_container(const sinsp_container_info& container_info, sinsp_threadinfo *thread);
	entry_ptr_t get_container(const std::string &id);
	void notify_new_container(const sinsp_container_info& container_info);
	template<typename E> bool resolve_container_impl(sinsp_threadinfo* tinfo, bool query_os_for_missing_info);
	template<typename E1, typename E2, typename... Args> bool resolve_container_impl(sinsp_threadinfo* tinfo, bool query_os_for_missing_info);
	bool resolve_container(sinsp_threadinfo* tinfo, bool query_os_for_missing_info);
	void dump_containers(scap_dumper_t* dumper);
	std::string get_container_name(sinsp_threadinfo* tinfo);

	// Set tinfo's m_category based on the container context.  It
	// will *not* change any category to NONE, so a threadinfo
	// that initially has a category will retain its category
	// across execs e.g. "sh -c /bin/true" execing /bin/true.
	void identify_category(sinsp_threadinfo *tinfo);

	bool container_exists(const std::string& container_id) const {
		return m_containers.find(container_id) != m_containers.end();
	}

	typedef std::function<void(const sinsp_container_info&, sinsp_threadinfo *)> new_container_cb;
	typedef std::function<void(const sinsp_container_info&)> remove_container_cb;
	void subscribe_on_new_container(new_container_cb callback);
	void subscribe_on_remove_container(remove_container_cb callback);

	void create_engines();
	void cleanup();

	void set_query_docker_image_info(bool query_image_info);
	void set_cri_extra_queries(bool extra_queries);
	void set_cri_socket_path(const std::string& path);
	void set_cri_timeout(int64_t timeout_ms);
	sinsp* get_inspector() { return m_inspector; }
private:
	std::string container_to_json(const sinsp_container_info& container_info);
	bool container_to_sinsp_event(const std::string& json, sinsp_evt* evt, std::shared_ptr<sinsp_threadinfo> tinfo);
	std::string get_docker_env(const Json::Value &env_vars, const std::string &mti);

	std::list<std::unique_ptr<libsinsp::container_engine::resolver>> m_container_engines;

	sinsp* m_inspector;
	std::unordered_map<std::string, sinsp_container_info> m_containers;
	uint64_t m_last_flush_time_ns;
	std::list<new_container_cb> m_new_callbacks;
	std::list<remove_container_cb> m_remove_callbacks;

	friend class test_helper;
};
