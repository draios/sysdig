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

#include "container_docker_common.h"
#include "container_mesos.h"
#include "sinsp.h"
#include "sinsp_int.h"

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


