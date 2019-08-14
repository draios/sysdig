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

#include "container_engine/cri.h"

#include <sys/stat.h>
#ifdef GRPC_INCLUDE_IS_GRPCPP
#	include <grpcpp/grpcpp.h>
#else
#	include <grpc++/grpc++.h>
#endif
#include "cri.pb.h"
#include "cri.grpc.pb.h"

#include "async_cgroup.h"
#include "async_key_value_source.h"
#include "runc.h"
#include "container_engine/mesos.h"
#include "grpc_channel_registry.h"
#include <cri.h>
#include "sinsp.h"
#include "sinsp_int.h"

using namespace libsinsp::cri;
using namespace libsinsp::container_engine;
using namespace libsinsp::runc;

constexpr const uint64_t cri_async_source::CGROUP_LOOKUP_DELAY_MS;

namespace {
// use asynchronous lookups?
bool s_async = true;
// get resource limits asynchronously?
bool s_async_limits = true;

bool init_cri()
{
	if(s_cri)
	{
		return true;
	}

	if(s_cri_unix_socket_path.empty()) {
		return false;
	}

	auto cri_path = scap_get_host_root() + s_cri_unix_socket_path;
	struct stat s = {};
	if(stat(cri_path.c_str(), &s) != 0 || (s.st_mode & S_IFMT) != S_IFSOCK) {
		return false;
	}

	std::shared_ptr<grpc::Channel> channel = libsinsp::grpc_channel_registry::get_channel("unix://" + cri_path);
	s_cri = runtime::v1alpha2::RuntimeService::NewStub(channel);
	s_cri_image = runtime::v1alpha2::ImageService::NewStub(channel);

	runtime::v1alpha2::VersionRequest vreq;
	runtime::v1alpha2::VersionResponse vresp;

	vreq.set_version("v1alpha2");
	grpc::ClientContext context;
	auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(s_cri_timeout);
	context.set_deadline(deadline);
	grpc::Status status = s_cri->Version(&context, vreq, &vresp);

	if (!status.ok())
	{
		g_logger.format(sinsp_logger::SEV_NOTICE, "cri: CRI runtime returned an error after version check at %s: %s",
				s_cri_unix_socket_path.c_str(), status.error_message().c_str());
		s_cri.reset(nullptr);
		s_cri_unix_socket_path = "";
		return false;
	}

	g_logger.format(sinsp_logger::SEV_INFO, "cri: CRI runtime: %s %s", vresp.runtime_name().c_str(), vresp.runtime_version().c_str());
	s_cri_runtime_type = get_cri_runtime_type(vresp.runtime_name());
	return true;
}

constexpr const cgroup_layout CRI_CGROUP_LAYOUT[] = {
	{"/", ""}, // non-systemd containerd
	{"/crio-", ""}, // non-systemd cri-o
	{"/cri-containerd-", ".scope"}, // systemd containerd
	{"/crio-", ".scope"}, // systemd cri-o
	{nullptr, nullptr}
};
}

bool cri_async_source::parse_containerd(const runtime::v1alpha2::ContainerStatusResponse& status, sinsp_container_info *container)
{
	const auto &info_it = status.info().find("info");
	if(info_it == status.info().end())
	{
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

bool cri_async_source::parse_cri(sinsp_container_info *container, const libsinsp::async_cgroup::delayed_cgroup_key& key)
{
	if(!s_cri)
	{
		// This isn't an error in the case where the
		// configured unix domain socket doesn't exist. In
		// that case, s_cri isn't initialized at all. Hence,
		// the DEBUG.
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"cri (%s): Could not parse cri (no s_cri object)",
				container->m_id.c_str());
		return false;
	}

	container->m_name = "";
	container->m_image = "";
	container->m_imageid = "";
	container->m_imagerepo = "";
	container->m_imagetag = "";
	container->m_imagedigest = "";

	runtime::v1alpha2::ContainerStatusRequest req;
	runtime::v1alpha2::ContainerStatusResponse resp;
	req.set_container_id(container->m_id);
	req.set_verbose(true);
	grpc::ClientContext context;
	auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(s_cri_timeout);
	context.set_deadline(deadline);
	grpc::Status status = s_cri->ContainerStatus(&context, req, &resp);

	g_logger.format(sinsp_logger::SEV_DEBUG,
			"cri (%s): Status from ContainerStatus: (%s)",
			container->m_id.c_str(),
			status.error_message().c_str());

	if(!status.ok())
	{
		if(is_pod_sandbox(container->m_id))
		{
			container->m_is_pod_sandbox = true;
			return true;
		}
		g_logger.format(sinsp_logger::SEV_DEBUG, "cri (%s): id is neither a container nor a pod sandbox",
			container->m_id.c_str());
		return false;
	}

	if(!resp.has_status())
	{
		ASSERT(false);
		return false;
	}

	const auto &resp_container = resp.status();
	container->m_name = resp_container.metadata().name();

	for(const auto &pair : resp_container.labels())
	{
		container->m_labels[pair.first] = pair.second;
	}

	parse_cri_image(resp_container, container);
	parse_cri_mounts(resp_container, container);

	if(parse_containerd(resp, container))
	{
		return true;
	}

	libsinsp::async_cgroup::delayed_cgroup_value limits;
	bool found_all = libsinsp::async_cgroup::get_cgroup_resource_limits(key, limits);

	container->m_memory_limit = limits.m_memory_limit;
	container->m_cpu_shares = limits.m_cpu_shares;
	container->m_cpu_quota = limits.m_cpu_quota;
	container->m_cpu_period = limits.m_cpu_period;

	if(s_async_limits && !found_all)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
			"cri (%s) not all limits read from cgroups, will retry in %d ms",
			container->m_id.c_str(), CGROUP_LOOKUP_DELAY_MS);

		auto manager = m_container_manager;
		auto cb = [manager](const libsinsp::async_cgroup::delayed_cgroup_key& key, const libsinsp::async_cgroup::delayed_cgroup_value& value) {
			libsinsp::async_cgroup::delayed_cgroup_lookup::update(manager, key, value);
		};

		m_async_cgroups.lookup_delayed(key, limits, std::chrono::milliseconds(CGROUP_LOOKUP_DELAY_MS), cb);
	}

	if(s_cri_extra_queries)
	{
		container->m_container_ip = get_container_ip(container->m_id);
		container->m_imageid = get_container_image_id(resp_container.image_ref());
	}

	return true;
}

void cri_async_source::run_impl()
{
	libsinsp::async_cgroup::delayed_cgroup_key key;

	while (dequeue_next_key(key))
	{
		sinsp_container_info res;

		res.m_successful = true;
		res.m_id = key.m_container_id;
		res.m_type = s_cri_runtime_type;

		if(!parse_cri(&res, key))
		{
			g_logger.format(sinsp_logger::SEV_ERROR, "Failed to get CRI metadata for container %s",
					key.m_container_id.c_str());
			res.m_successful = false;
		}

		// Return a result object either way, to ensure any
		// new container callbacks are called.
		store_value(key, res);
	}
}

void cri::cleanup()
{
	if (m_cri_info_source)
	{
		m_cri_info_source->quiesce();
	}
	m_cri_info_source.reset(nullptr);
	s_cri.reset(nullptr);
	s_cri_image.reset(nullptr);
	s_cri_extra_queries = true;
}

void cri::set_cri_socket_path(const std::string& path)
{
	s_cri_unix_socket_path = path;
}

void cri::set_cri_timeout(int64_t timeout_ms)
{
	s_cri_timeout = timeout_ms;
}

void cri::set_extra_queries(bool extra_queries)
{
	s_cri_extra_queries = extra_queries;
}

void cri::set_async(bool async) {
	s_async = async;
}

void cri::set_async_limits(bool async_limits) {
	s_async_limits = async_limits;
}

bool cri::resolve(sinsp_container_manager* manager, sinsp_threadinfo* tinfo, bool query_os_for_missing_info)
{
	std::string container_id;

	if(!matches_runc_cgroups(tinfo, CRI_CGROUP_LAYOUT, container_id))
	{
		return false;
	}
	tinfo->m_container_id = container_id;

	if(!init_cri())
	{
		return false;
	}

	if(!m_cri_info_source)
	{
		// we do 4 gRPC requests so set the timeout to 5x the individual request timeout
		// s_cri_timeout is in milliseconds and we want nanoseconds -- that's where the 1000000 factor comes from
		auto cri_source = new cri_async_source(manager, s_cri_timeout * 5 * 1000000);
		m_cri_info_source.reset(cri_source);
	}
	sinsp_container_info *container_info = manager->get_container(container_id);
	sinsp_container_info sync_container_info;

	if (!container_info ||
	    container_info->query_anyway(s_cri_runtime_type))
	{
		if (query_os_for_missing_info)
		{
			libsinsp::async_cgroup::delayed_cgroup_key key(
				container_id,
				tinfo->get_cgroup("cpu"),
				tinfo->get_cgroup("memory"));
			if(s_async)
			{
				container_info = manager->get_or_create_container(
					s_cri_runtime_type, container_id, "", tinfo);

				m_cri_info_source->lookup_container(key, manager);
			}
			else
			{
				container_info = &sync_container_info;
				g_logger.format(sinsp_logger::SEV_DEBUG,
						"cri (%s): Performing sync lookup",
						container_id.c_str());

				sync_container_info.m_type = s_cri_runtime_type;
				sync_container_info.m_id = container_id;
				sync_container_info.m_successful = m_cri_info_source->parse_cri(
					&sync_container_info, key);

				g_logger.format(sinsp_logger::SEV_DEBUG,
					"cri (%s) sync lookup done, successful=%s",
					container_id.c_str(), sync_container_info.m_successful ? "true" : "false");

				sync_container_info.m_metadata_complete = true;
				if(manager->update_container(sync_container_info) && sync_container_info.m_successful)
				{
					manager->notify_new_container(sync_container_info);
				}
			}
		}
		if (container_info && mesos::set_mesos_task_id(container_info, tinfo))
		{
			g_logger.format(sinsp_logger::SEV_DEBUG,
					"cri (%s) Mesos CRI container, Mesos task ID: [%s]",
					container_id.c_str(), container_info->m_mesos_task_id.c_str());
		}
	}

	return container_info ? container_info->m_metadata_complete : true;
}
