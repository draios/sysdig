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

#include "container_info.h"

#if !defined(_WIN32) && !defined(CYGWING_AGENT) && defined(HAS_CAPTURE)
#include <curl/curl.h>
#include <curl/easy.h>
#include <curl/multi.h>

#ifndef CONTAINER_CPP
// a class that no-op extends RuntimeService::Stub from the CRI GRPC header
// we can't include the header due to conflicts with ncurses in table.cc
// and  we can't forward-declare a nested class
class RuntimeService_Stub;
#endif
#endif

enum sinsp_docker_response
{
	RESP_OK = 0,
	RESP_BAD_REQUEST = 1,
	RESP_ERROR = 2
};

class sinsp_container_manager;

typedef std::function<bool(sinsp_container_manager* manager, sinsp_threadinfo* tinfo, bool query_os_for_missing_info)> sinsp_container_engine;

class sinsp_container_engine_docker
{
public:
	sinsp_container_engine_docker();

	bool resolve(sinsp_container_manager* manager, sinsp_threadinfo* tinfo, bool query_os_for_missing_info);
	static void cleanup();
	static void set_query_image_info(bool query_image_info);
	static void parse_json_mounts(const Json::Value &mnt_obj, vector<sinsp_container_info::container_mount_info> &mounts);

protected:
#if !defined(CYGWING_AGENT) && defined(HAS_CAPTURE)
	static size_t curl_write_callback(const char* ptr, size_t size, size_t nmemb, string* json);
#endif
	sinsp_docker_response get_docker(sinsp_container_manager* manager, const string& url, string &json);
	bool parse_docker(sinsp_container_manager* manager, sinsp_container_info *container, sinsp_threadinfo* tinfo);
	bool parse_containerd(sinsp_container_manager* manager, sinsp_container_info *container, sinsp_threadinfo* tinfo);

	string m_unix_socket_path;
	string m_containerd_unix_socket_path;
	string m_api_version;
	static bool m_query_image_info;
#if !defined(CYGWING_AGENT) && defined(HAS_CAPTURE)
	static CURLM *m_curlm;
	static CURL *m_curl;

	static unique_ptr<RuntimeService_Stub> m_containerd;
#endif
};

class sinsp_container_manager
{
public:
	sinsp_container_manager(sinsp* inspector);
	virtual ~sinsp_container_manager();

	const unordered_map<string, sinsp_container_info>* get_containers();
	bool remove_inactive_containers();
	void add_container(const sinsp_container_info& container_info, sinsp_threadinfo *thread);
	sinsp_container_info * get_container(const string &id);
	void notify_new_container(const sinsp_container_info& container_info);
	template<typename E> bool resolve_container_impl(sinsp_threadinfo* tinfo, bool query_os_for_missing_info);
	template<typename E1, typename E2, typename... Args> bool resolve_container_impl(sinsp_threadinfo* tinfo, bool query_os_for_missing_info);
	bool resolve_container(sinsp_threadinfo* tinfo, bool query_os_for_missing_info);
	void dump_containers(scap_dumper_t* dumper);
	string get_container_name(sinsp_threadinfo* tinfo);

	// Set tinfo's is_container_healthcheck attribute to true if
	// it is identified as a container healthcheck. It will *not*
	// set it to false by default, so a threadinfo that is
	// initially identified as a health check will remain one
	// across execs e.g. "sh -c /bin/true" execing /bin/true.
	void identify_healthcheck(sinsp_threadinfo *tinfo);

	bool container_exists(const string& container_id) const {
		return m_containers.find(container_id) != m_containers.end();
	}

	typedef std::function<void(const sinsp_container_info&, sinsp_threadinfo *)> new_container_cb;
	typedef std::function<void(const sinsp_container_info&)> remove_container_cb;
	void subscribe_on_new_container(new_container_cb callback);
	void subscribe_on_remove_container(remove_container_cb callback);

	void cleanup();

	void set_query_docker_image_info(bool query_image_info);
	sinsp* get_inspector() { return m_inspector; }
private:
	string container_to_json(const sinsp_container_info& container_info);
	bool container_to_sinsp_event(const string& json, sinsp_evt* evt);
	string get_docker_env(const Json::Value &env_vars, const string &mti);

	sinsp* m_inspector;
	unordered_map<string, sinsp_container_info> m_containers;
	uint64_t m_last_flush_time_ns;
	list<new_container_cb> m_new_callbacks;
	list<remove_container_cb> m_remove_callbacks;
};

template<typename E> bool sinsp_container_manager::resolve_container_impl(sinsp_threadinfo* tinfo, bool query_os_for_missing_info)
{
	E engine;
	return engine.resolve(this, tinfo, query_os_for_missing_info);
}

template<typename E1, typename E2, typename... Args> bool sinsp_container_manager::resolve_container_impl(sinsp_threadinfo* tinfo, bool query_os_for_missing_info)
{
	if (resolve_container_impl<E1>(tinfo, query_os_for_missing_info))
	{
		return true;
	}
	return resolve_container_impl<E2, Args...>(tinfo, query_os_for_missing_info);
}
