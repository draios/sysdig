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

#include "container_cri.h"
#include "container_docker.h"

#include <sys/stat.h>
#include <grpc++/grpc++.h>
#include "cri.pb.h"
#include "cri.grpc.pb.h"

#include "container_mesos.h"
#include "sinsp.h"
#include "sinsp_int.h"

namespace {
string cri_unix_socket_path = "/run/containerd/containerd.sock";
unique_ptr<runtime::v1alpha2::RuntimeService::Stub> cri = nullptr;
int64_t cri_timeout = 1000;
sinsp_container_type cri_runtime_type = CT_CRI;

sinsp_container_type get_cri_runtime_type(const std::string& runtime_name)
{
	if (runtime_name == "containerd")
	{
		return CT_CONTAINERD;
	}
	else
	{
		return CT_CRI;
	}
}

bool parse_cri_image(const runtime::v1alpha2::ContainerStatus &status, sinsp_container_info *container)
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
	container->m_image = status.image().image();
	return true;
}

bool parse_cri_mounts(const runtime::v1alpha2::ContainerStatus &status, sinsp_container_info *container)
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

bool parse_cri_env(const Json::Value &info, sinsp_container_info *container)
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

bool parse_cri_json_image(const Json::Value &info, sinsp_container_info *container)
{
	const Json::Value *image;
	if (!walk_down_json(info, &image, "config", "image", "image") || !image->isString())
	{
		return false;
	}

	auto image_str = image->asString();
	auto pos = image_str.find(':');
	if (pos == string::npos)
	{
		container->m_imageid = move(image_str);
	}
	else
	{
		container->m_imageid = image_str.substr(pos+1);
	}

	return true;
}

bool parse_cri_runtime_spec(const Json::Value &info, sinsp_container_info *container)
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

uint32_t get_pod_sandbox_ip(const std::string& pod_sandbox_id)
{
	runtime::v1alpha2::PodSandboxStatusRequest req;
	runtime::v1alpha2::PodSandboxStatusResponse resp;
	req.set_pod_sandbox_id(pod_sandbox_id);
	req.set_verbose(true);
	grpc::ClientContext context;
	auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(cri_timeout);
	context.set_deadline(deadline);
	grpc::Status status = cri->PodSandboxStatus(&context, req, &resp);

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
}

sinsp_container_engine_cri::sinsp_container_engine_cri()
{
	if(cri || cri_unix_socket_path.empty()) {
		return;
	}

	auto cri_path = scap_get_host_root() + cri_unix_socket_path;
	struct stat s;
	if(stat(cri_path.c_str(), &s) != 0 || (s.st_mode & S_IFMT) != S_IFSOCK) {
		return;
	}

	cri = runtime::v1alpha2::RuntimeService::NewStub(
		grpc::CreateChannel("unix://" + cri_path, grpc::InsecureChannelCredentials()));

	runtime::v1alpha2::VersionRequest vreq;
	runtime::v1alpha2::VersionResponse vresp;

	vreq.set_version("v1alpha2");
	grpc::ClientContext context;
	auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(cri_timeout);
	context.set_deadline(deadline);
	grpc::Status status = cri->Version(&context, vreq, &vresp);

	if (!status.ok())
	{
		// we could disable CRI support here...
		return;
	}

	cri_runtime_type = get_cri_runtime_type(vresp.runtime_name());
}

void sinsp_container_engine_cri::cleanup()
{
	cri.reset(nullptr);
}

void sinsp_container_engine_cri::set_cri_socket_path(const std::string& path)
{
	cri_unix_socket_path = path;
}

void sinsp_container_engine_cri::set_cri_timeout(int64_t timeout_ms)
{
	cri_timeout = timeout_ms;
}

bool parse_cri(sinsp_container_manager* manager, sinsp_container_info *container, sinsp_threadinfo* tinfo)
{
	if (!cri)
	{
		return false;
	}

	runtime::v1alpha2::ContainerStatusRequest req;
	runtime::v1alpha2::ContainerStatusResponse resp;
	req.set_container_id(container->m_id);
	req.set_verbose(true);
	grpc::ClientContext context;
	auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(cri_timeout);
	context.set_deadline(deadline);
	grpc::Status status = cri->ContainerStatus(&context, req, &resp);
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
	container->m_type = cri_runtime_type;

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
	parse_cri_json_image(root, container);
	parse_cri_runtime_spec(root, container);

	if(root.isMember("sandboxID") && root["sandboxID"].isString())
	{
		const auto pod_sandbox_id = root["sandboxID"].asString();
		container->m_container_ip = ntohl(get_pod_sandbox_ip(pod_sandbox_id));
	}

	return true;
}

bool sinsp_container_engine_cri::resolve(sinsp_container_manager* manager, sinsp_threadinfo* tinfo, bool query_os_for_missing_info)
{
	sinsp_container_info container_info;

	if(sinsp_container_engine_docker::detect_docker(tinfo, container_info.m_id))
	{
		container_info.m_type = cri_runtime_type;
	}
	else
	{
		return false;
	}
	tinfo->m_container_id = container_info.m_id;
	if (!manager->container_exists(container_info.m_id))
	{
		if (query_os_for_missing_info)
		{
			parse_cri(manager, &container_info, tinfo);
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
