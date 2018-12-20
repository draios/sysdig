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

#if defined(HAS_CAPTURE)
#include <sys/stat.h>
#include <grpc++/grpc++.h>
#include "cri.pb.h"
#include "cri.grpc.pb.h"

#define CONTAINER_CPP
typedef runtime::v1alpha2::RuntimeService::Stub RuntimeService_Stub;
#endif

#include "container_docker.h"
#include "container_mesos.h"
#include "sinsp.h"
#include "sinsp_int.h"

#if defined(HAS_CAPTURE)
string sinsp_container_engine_docker::m_unix_socket_path = "/var/run/docker.sock";
string sinsp_container_engine_docker::m_cri_unix_socket_path = "/run/containerd/containerd.sock";
CURLM *sinsp_container_engine_docker::m_curlm = NULL;
CURL *sinsp_container_engine_docker::m_curl = NULL;
unique_ptr<runtime::v1alpha2::RuntimeService::Stub> sinsp_container_engine_docker::m_cri = nullptr;
#endif

sinsp_container_engine_docker::sinsp_container_engine_docker() :
	m_api_version("/v1.24")
{
#if defined(HAS_CAPTURE)
	if(!m_curlm)
	{
		m_curl = curl_easy_init();
		m_curlm = curl_multi_init();

		if(m_curlm)
		{
			curl_multi_setopt(m_curlm, CURLMOPT_PIPELINING, CURLPIPE_HTTP1|CURLPIPE_MULTIPLEX);
		}

		if(m_curl)
		{
			auto docker_path = scap_get_host_root() + m_unix_socket_path;
			curl_easy_setopt(m_curl, CURLOPT_UNIX_SOCKET_PATH, docker_path.c_str());
			curl_easy_setopt(m_curl, CURLOPT_HTTPGET, 1);
			curl_easy_setopt(m_curl, CURLOPT_FOLLOWLOCATION, 1);
			curl_easy_setopt(m_curl, CURLOPT_WRITEFUNCTION, curl_write_callback);
		}
	}

	if(!m_cri && !m_cri_unix_socket_path.empty())
	{
		auto cri_path = scap_get_host_root() + m_cri_unix_socket_path;
		struct stat s;
		if(stat(cri_path.c_str(), &s) == 0 && (s.st_mode & S_IFMT) == S_IFSOCK)
		{

			m_cri = runtime::v1alpha2::RuntimeService::NewStub(
				grpc::CreateChannel("unix://" + cri_path, grpc::InsecureChannelCredentials()));
		}
	}
#endif
}

void sinsp_container_engine_docker::cleanup()
{
#if defined(HAS_CAPTURE)
	curl_easy_cleanup(m_curl);
	m_curl = NULL;
	curl_multi_cleanup(m_curlm);
	m_curlm = NULL;

	m_cri.reset(nullptr);
#endif
}

#if defined(HAS_CAPTURE)
size_t sinsp_container_engine_docker::curl_write_callback(const char* ptr, size_t size, size_t nmemb, string* json)
{
	const std::size_t total = size * nmemb;
	json->append(ptr, total);
	return total;
}
#endif

std::string sinsp_container_engine_docker::build_request(const std::string &url)
{
	return "http://localhost" + m_api_version + url;
}

#if defined(HAS_CAPTURE)
bool sinsp_container_engine_docker::parse_cri_image(const runtime::v1alpha2::ContainerStatus &status, sinsp_container_info *container)
{
	// image_ref may be one of two forms:
	// host/image@sha256:digest
	// sha256:digest
	const auto& image_ref = status.image_ref();
	auto digest_start = image_ref.find("sha256:");
	if (digest_start != string::npos)
	{
		container->m_imagedigest = image_ref.substr(digest_start);
	}

	string hostname, port, digest;
	sinsp_utils::split_container_image(status.image().image(),
					   hostname,
					   port,
					   container->m_imagerepo,
					   container->m_imagetag,
					   digest,
					   false);

	return true;
}

bool sinsp_container_engine_docker::parse_cri_mounts(const runtime::v1alpha2::ContainerStatus &status, sinsp_container_info *container)
{
	for (const auto& mount : status.mounts())
	{
		const char* propagation;
		switch(mount.propagation()) {
			case runtime::v1alpha2::MountPropagation::PROPAGATION_PRIVATE:
				propagation = "private";
				break;
			case runtime::v1alpha2::MountPropagation::PROPAGATION_HOST_TO_CONTAINER:
				propagation = "rslave";
				break;
			case runtime::v1alpha2::MountPropagation::PROPAGATION_BIDIRECTIONAL:
				propagation = "rshared";
				break;
			default:
				propagation = "unknown";
				break;
		}
		container->m_mounts.emplace_back(
			mount.host_path(),
			mount.container_path(),
			"",
			!mount.readonly(),
			propagation);
	}
	return true;

}

namespace {
bool walk_down_json(const Json::Value& root, const Json::Value** out, const std::string& key)
{
	if (root.isMember(key))
	{
		*out = &root[key];
		return true;
	}
	return false;
}

template<typename... Args> bool walk_down_json(const Json::Value& root, const Json::Value** out, const std::string& key, Args... args)
{
	if (root.isMember(key))
	{
		return walk_down_json(root[key], out, args...);
	}
	return false;
}

bool set_numeric(const Json::Value& dict, const std::string& key, int64_t& val)
{
	if (!dict.isMember(key))
	{
		return false;
	}
	const auto& json_val = dict[key];
	if (!json_val.isNumeric())
	{
		return false;
	}
	val = json_val.asInt64();
	return true;
}

}

bool sinsp_container_engine_docker::parse_cri_env(const Json::Value &info, sinsp_container_info *container)
{
	const Json::Value *envs;
	if (!walk_down_json(info, &envs, "config", "envs") || !envs->isArray())
	{
		return false;
	}

	for (const auto& env_var : *envs)
	{
		const auto& key = env_var["key"];
		const auto& value = env_var["value"];

		if (key.isString() && value.isString())
		{
			auto var = key.asString();
			var += '=';
			var += value.asString();
			container->m_env.emplace_back(var);
		}
	}

	return true;
}

bool sinsp_container_engine_docker::parse_cri_runtime_spec(const Json::Value &info, sinsp_container_info *container)
{
	const Json::Value *linux = nullptr;
	if(!walk_down_json(info, &linux, "runtimeSpec", "linux") || !linux->isArray())
	{
		return false;
	}

	const Json::Value *memory = nullptr;
	if(walk_down_json(*linux, &memory, "resources", "memory"))
	{
		set_numeric(*memory, "limit", container->m_memory_limit);
		container->m_swap_limit = container->m_memory_limit;
	}

	const Json::Value *cpu = nullptr;
	if(walk_down_json(*linux, &cpu, "resources", "cpu") && cpu->isObject())
	{
		set_numeric(*cpu, "shares", container->m_cpu_shares);
		set_numeric(*cpu, "quota", container->m_cpu_quota);
		set_numeric(*cpu, "period", container->m_cpu_period);
	}

	const Json::Value *privileged;
	if(walk_down_json(*linux, &privileged, "security_context", "privileged") && privileged->isBool())
	{
		container->m_privileged = privileged->asBool();
	}

	return true;
}

uint32_t sinsp_container_engine_docker::get_pod_sandbox_ip(const std::string& pod_sandbox_id)
{
	runtime::v1alpha2::PodSandboxStatusRequest req;
	runtime::v1alpha2::PodSandboxStatusResponse resp;
	req.set_pod_sandbox_id(pod_sandbox_id);
	req.set_verbose(true);
	grpc::ClientContext context;
	auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(1000);
	context.set_deadline(deadline);
	grpc::Status status = m_cri->PodSandboxStatus(&context, req, &resp);

	if (!status.ok()) {
		return 0;
	}

	const auto& pod_ip = resp.status().network().ip();
	if (pod_ip.empty()) {
		return 0;
	}

	uint32_t ip;
	if (inet_pton(AF_INET, pod_ip.c_str(), &ip) == -1)
	{
		ASSERT(false);
		return 0;
	}
	else
	{
		return ip;
	}
}
#endif

bool sinsp_container_engine_docker::parse_containerd(sinsp_container_manager* manager, sinsp_container_info *container, sinsp_threadinfo* tinfo)
{
#if defined(HAS_CAPTURE)
	runtime::v1alpha2::ContainerStatusRequest req;
	runtime::v1alpha2::ContainerStatusResponse resp;
	req.set_container_id(container->m_id);
	req.set_verbose(true);
	grpc::ClientContext context;
	auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(1000);
	context.set_deadline(deadline);
	grpc::Status status = m_cri->ContainerStatus(&context, req, &resp);
	if (!status.ok()) {
		return false;
	}

	if (!resp.has_status())
	{
		ASSERT(false);
		return false;
	}

	const auto& resp_container = resp.status();
	container->m_name = resp_container.metadata().name();

	for (const auto& pair : resp_container.labels())
	{
		container->m_labels[pair.first] = pair.second;
	}

	parse_cri_image(resp_container, container);
	parse_cri_mounts(resp_container, container);

	const auto& info_it = resp.info().find("info");
	if (info_it == resp.info().end())
	{
		ASSERT(false);
		return false;
	}
	Json::Value root;
	Json::Reader reader;
	if(!reader.parse(info_it->second, root))
	{
		ASSERT(false);
		return false;
	}

	parse_cri_env(root, container);
	parse_cri_runtime_spec(root, container);

	if(root.isMember("sandboxID") && root["sandboxID"].isString())
	{
		const auto pod_sandbox_id = root["sandboxID"].asString();
		container->m_container_ip = ntohl(get_pod_sandbox_ip(pod_sandbox_id));
	}

	return true;
#else
	ASSERT(false);
	return false;
#endif
}

bool sinsp_container_engine_docker::resolve(sinsp_container_manager* manager, sinsp_threadinfo* tinfo, bool query_os_for_missing_info)
{
	sinsp_container_info container_info;
	bool matches = false;

	for(auto it = tinfo->m_cgroups.begin(); it != tinfo->m_cgroups.end(); ++it)
	{
		string cgroup = it->second;
		size_t pos;

		//
		// Non-systemd Docker
		//
		pos = cgroup.find_last_of("/");
		if(pos != string::npos)
		{
			if(cgroup.length() - pos - 1 == 64 &&
			   cgroup.find_first_not_of("0123456789abcdefABCDEF", pos + 1) == string::npos)
			{
				container_info.m_type = CT_DOCKER;
				container_info.m_id = cgroup.substr(pos + 1, 12);
				matches = true;
				break;
			}
		}

		//
		// systemd Docker
		//
		pos = cgroup.find("docker-");
		if(pos != string::npos)
		{
			size_t pos2 = cgroup.find(".scope");
			if(pos2 != string::npos &&
			   pos2 - pos - sizeof("docker-") + 1 == 64)
			{
				container_info.m_type = CT_DOCKER;
				container_info.m_id = cgroup.substr(pos + sizeof("docker-") - 1, 12);
				matches = true;
				break;
			}
		}
	}

	if (!matches)
		return false;

	tinfo->m_container_id = container_info.m_id;
	if (!manager->container_exists(container_info.m_id))
	{
		if (query_os_for_missing_info)
		{
			if (!parse_docker(manager, &container_info, tinfo) && m_cri)
			{
				parse_containerd(manager, &container_info, tinfo);
			}
		}
		if (sinsp_container_engine_mesos::set_mesos_task_id(&container_info, tinfo))
		{
			g_logger.format(sinsp_logger::SEV_DEBUG,
					"Mesos Docker container: [%s], Mesos task ID: [%s]",
					container_info.m_id.c_str(), container_info.m_mesos_task_id.c_str());
		}
		manager->add_container(container_info, tinfo);
		manager->notify_new_container(container_info);
	}
	return true;
}

sinsp_docker_response sinsp_container_engine_docker::get_docker(sinsp_container_manager* manager, const string& url, string &json)
{
#ifdef HAS_CAPTURE
	if(curl_easy_setopt(m_curl, CURLOPT_URL, url.c_str()) != CURLE_OK)
	{
		ASSERT(false);
		return sinsp_docker_response::RESP_ERROR;
	}
	if(curl_easy_setopt(m_curl, CURLOPT_WRITEDATA, &json) != CURLE_OK)
	{
		ASSERT(false);
		return sinsp_docker_response::RESP_ERROR;
	}

	if(curl_multi_add_handle(m_curlm, m_curl) != CURLM_OK)
	{
		ASSERT(false);
		return sinsp_docker_response::RESP_ERROR;
	}

	while(true)
	{
		int still_running;
		CURLMcode res = curl_multi_perform(m_curlm, &still_running);
		if(res != CURLM_OK)
		{
			ASSERT(false);
			return sinsp_docker_response::RESP_ERROR;
		}

		if(still_running == 0)
		{
			break;
		}

		int numfds;
		res = curl_multi_wait(m_curlm, NULL, 0, -1, &numfds);
		if(res != CURLM_OK)
		{
			ASSERT(false);
			return sinsp_docker_response::RESP_ERROR;
		}
	}

	if(curl_multi_remove_handle(m_curlm, m_curl) != CURLM_OK)
	{
		ASSERT(false);
		return sinsp_docker_response::RESP_ERROR;
	}

	long http_code = 0;
	if(curl_easy_getinfo(m_curl, CURLINFO_RESPONSE_CODE, &http_code) != CURLE_OK)
	{
		ASSERT(false);
		return sinsp_docker_response::RESP_ERROR;
	}
	switch(http_code)
	{
		case 0: /* connection failed, apparently */
			return sinsp_docker_response::RESP_ERROR;
		case 200:
			return sinsp_docker_response::RESP_OK;
		default:
			return sinsp_docker_response::RESP_BAD_REQUEST;
	}

	return sinsp_docker_response::RESP_OK;
#else
	return sinsp_docker_response::RESP_ERROR;
#endif
}
