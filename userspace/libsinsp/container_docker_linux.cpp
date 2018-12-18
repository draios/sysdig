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

#include <grpc++/grpc++.h>
#include "cri.pb.h"
#include "cri.grpc.pb.h"

#define CONTAINER_CPP
typedef runtime::v1alpha2::RuntimeService::Stub RuntimeService_Stub;

#include "container_docker.h"
#include "container_mesos.h"
#include "sinsp.h"
#include "sinsp_int.h"

#if defined(HAS_CAPTURE)
CURLM *sinsp_container_engine_docker::m_curlm = NULL;
CURL *sinsp_container_engine_docker::m_curl = NULL;
unique_ptr<runtime::v1alpha2::RuntimeService::Stub> sinsp_container_engine_docker::m_containerd = nullptr;
#endif

sinsp_container_engine_docker::sinsp_container_engine_docker() :
#if defined(HAS_CAPTURE)
	m_unix_socket_path(string(scap_get_host_root()) + "/var/run/docker.sock"),
	m_containerd_unix_socket_path("unix://" + string(scap_get_host_root()) + "/run/containerd/containerd.sock"),
#endif
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
			curl_easy_setopt(m_curl, CURLOPT_UNIX_SOCKET_PATH, m_unix_socket_path.c_str());
			curl_easy_setopt(m_curl, CURLOPT_HTTPGET, 1);
			curl_easy_setopt(m_curl, CURLOPT_FOLLOWLOCATION, 1);
			curl_easy_setopt(m_curl, CURLOPT_WRITEFUNCTION, curl_write_callback);
		}
	}

	if(!m_containerd)
	{
		m_containerd = runtime::v1alpha2::RuntimeService::NewStub(
			grpc::CreateChannel(m_containerd_unix_socket_path, grpc::InsecureChannelCredentials()));
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

	m_containerd.reset(nullptr);
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

bool sinsp_container_engine_docker::parse_containerd(sinsp_container_manager* manager, sinsp_container_info *container, sinsp_threadinfo* tinfo)
{
#if defined(HAS_CAPTURE)
	runtime::v1alpha2::ContainerStatusRequest req;
	runtime::v1alpha2::ContainerStatusResponse resp;
	req.set_container_id(container->m_id);
	req.set_verbose(true);
	grpc::ClientContext context;
	// XXX async
	grpc::Status status = m_containerd->ContainerStatus(&context, req, &resp);
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

	// image_ref may be one of two forms:
	// host/image@sha256:digest
	// sha256:digest
	const auto& image_ref = resp_container.image_ref();
	auto digest_start = image_ref.find("sha256:");
	if (digest_start != string::npos)
	{
		container->m_imagedigest = image_ref.substr(digest_start);
	}

	string hostname, port, digest;
	sinsp_utils::split_container_image(resp_container.image().image(),
					   hostname,
					   port,
					   container->m_imagerepo,
					   container->m_imagetag,
					   digest,
					   false);

	for (const auto& mount : resp_container.mounts())
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

	for (const auto& pair : resp_container.labels())
	{
		container->m_labels[pair.first] = pair.second;
	}

	const auto& info_it = resp.info().find("info");
	if (info_it == resp.info().end())
	{
		ASSERT(false);
		return false;
	}
	Json::Value root;
	Json::Reader reader;
	bool parsingSuccessful = reader.parse(info_it->second, root);
	if(!parsingSuccessful)
	{
		ASSERT(false);
		return false;
	}

	const Json::Value& config = root["config"];
	const Json::Value& envs = config["envs"];

	for (const auto& env_var : envs)
	{
		auto key = env_var["key"].asString();
		auto value = env_var["value"].asString();
		container->m_env.emplace_back(key + '=' + value);
	}

	const Json::Value& resources = root["runtimeSpec"]["linux"]["resources"];
	container->m_memory_limit = resources["memory"]["limit"].asInt64();
	container->m_swap_limit = container->m_memory_limit;

	const Json::Value& cpu = resources["cpu"];
	container->m_cpu_shares = cpu["shares"].asInt64();
	container->m_cpu_quota = cpu["quota"].asInt64();
	container->m_cpu_period = cpu["period"].asInt64();

	const Json::Value& privileged = root["runtimeSpec"]["linux"]["security_context"]["privileged"];
	container->m_privileged = privileged.asBool();

	const auto pod_sandbox_id = root["sandboxID"].asString();
	runtime::v1alpha2::PodSandboxStatusRequest psreq;
	runtime::v1alpha2::PodSandboxStatusResponse psresp;
	psreq.set_pod_sandbox_id(pod_sandbox_id);
	psreq.set_verbose(true);
	grpc::ClientContext pscontext;
	// XXX async
	status = m_containerd->PodSandboxStatus(&pscontext, psreq, &psresp);
	if (!status.ok()) {
		return false;
	}

	const auto& pod_ip = psresp.status().network().ip();
	if (!pod_ip.empty())
	{
		long ip;
		if (inet_pton(AF_INET, pod_ip.c_str(), &ip) == -1)
		{
			ASSERT(false);
		}
		else
		{
			container->m_container_ip = ntohl(ip);
		}
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
			if (!parse_docker(manager, &container_info, tinfo))
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
