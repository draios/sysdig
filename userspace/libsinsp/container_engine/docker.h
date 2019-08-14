/*
Copyright (C) 2013-2019 Draios Inc dba Sysdig.

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

#include <memory>
#include <string>
#include <vector>
#include <atomic>

#if !defined(_WIN32)
#include <curl/curl.h>
#include <curl/easy.h>
#include <curl/multi.h>
#endif

#include "json/json.h"

#include "async_key_value_source.h"

#include "container.h"
#include "container_info.h"

#include "container_engine/container_engine.h"

class sinsp;
class sinsp_threadinfo;

namespace libsinsp {
namespace container_engine {

class docker_async_source : public sysdig::async_key_value_source<std::string, sinsp_container_info>
{
	enum docker_response
	{
		RESP_OK = 0,
		RESP_BAD_REQUEST = 1,
		RESP_ERROR = 2
	};

public:
#ifdef _WIN32
	docker_async_source(uint64_t max_wait_ms, uint64_t ttl_ms, sinsp *inspector);
#else
	docker_async_source(uint64_t max_wait_ms, uint64_t ttl_ms, sinsp *inspector, std::string socket_path);
#endif
	virtual ~docker_async_source();

	static void set_query_image_info(bool query_image_info);

protected:
	void run_impl();

private:
	// These 4 methods are OS-dependent and defined in docker_{linux,win}.cpp
	void init_docker_conn();
	void free_docker_conn();
	std::string build_request(const std::string& url);
	docker_response get_docker(const std::string& url, std::string &json);

	bool parse_docker(std::string &container_id, sinsp_container_info &container);

	// Look for a pod specification in this container's labels and
	// if found set spec to the pod spec.
	bool get_k8s_pod_spec(const Json::Value &config_obj,
			      Json::Value &spec);

	std::string normalize_arg(const std::string &arg);

	// Parse a healthcheck out of the provided healthcheck object,
	// updating the container info with any healthcheck found.
	void parse_healthcheck(const Json::Value &healthcheck_obj,
			       sinsp_container_info &container);

	// Parse either a readiness or liveness probe out of the
	// provided object, updating the container info with any probe
	// found. Returns true if the healthcheck/livenesss/readiness
	// probe info was found and could be parsed.
	bool parse_liveness_readiness_probe(const Json::Value &probe_obj,
					    sinsp_container_info::container_health_probe::probe_type ptype,
					    sinsp_container_info &container);

	// See if this config has a io.kubernetes.sandbox.id label
	// referring to a different container. (NOTE: this is not the
	// same as docker's sandbox id, which refers to networks.) If
	// it does, try to copy the health checks from that container
	// to the provided container_info pointer. Returns true if a
	// sandbox container id was found, the corresponding container
	// was found, and if the health checks could be copied from
	// that container.
	bool get_sandbox_liveness_readiness_probes(const Json::Value &config_obj,
						   sinsp_container_info *container);

	// Parse all healthchecks/liveness probes/readiness probes out
	// of the provided object, updating the container info as required.
	void parse_health_probes(const Json::Value &config_obj,
				 sinsp_container_info &container);

	sinsp *m_inspector;

	std::string m_api_version;

#ifndef _WIN32
	std::string m_docker_unix_socket_path;
	CURLM *m_curlm;
	CURL *m_curl;
#endif

	static bool m_query_image_info;
};

class docker : public resolver
{
public:
	docker();

	bool resolve(sinsp_container_manager* manager, sinsp_threadinfo* tinfo, bool query_os_for_missing_info) override;
	void cleanup() override;
	static void parse_json_mounts(const Json::Value &mnt_obj, std::vector<sinsp_container_info::container_mount_info> &mounts);

	// Container name only set for windows. For linux name must be fetched via lookup
	static bool detect_docker(const sinsp_threadinfo* tinfo, std::string& container_id, std::string &container_name);

#ifndef _WIN32
	static void set_docker_sock(std::string docker_sock) {
		m_docker_sock = std::move(docker_sock);
	}
#endif
protected:
	void parse_docker_async(const std::string& container_id, sinsp_container_manager *manager);

	std::unique_ptr<docker_async_source> m_docker_info_source;

	static std::string s_incomplete_info_name;
#ifndef _WIN32
	static std::string m_docker_sock;
#endif
};
}
}
