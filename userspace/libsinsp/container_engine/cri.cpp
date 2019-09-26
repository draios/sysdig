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

#include "cgroup_limits.h"
#include "runc.h"
#include "container_engine/mesos.h"
#include "grpc_channel_registry.h"
#include <cri.h>
#include "sinsp.h"
#include "sinsp_int.h"

using namespace libsinsp::cri;
using namespace libsinsp::container_engine;
using namespace libsinsp::runc;

namespace {
// do the CRI communication asynchronously
bool s_async = true;
// delay before talking to CRI/cgroups
uint64_t s_cri_lookup_delay_ms = 500;

constexpr const cgroup_layout CRI_CGROUP_LAYOUT[] = {
	{"/", ""}, // non-systemd containerd
	{"/crio-", ""}, // non-systemd cri-o
	{"/cri-containerd-", ".scope"}, // systemd containerd
	{"/crio-", ".scope"}, // systemd cri-o
	{nullptr, nullptr}
};
}

bool cri_async_source::parse_containerd(const runtime::v1alpha2::ContainerStatusResponse& status, sinsp_container_info &container)
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
		container.m_container_ip = ntohl(get_pod_sandbox_ip(pod_sandbox_id));
	}

	return true;
}

bool cri_async_source::parse_cri(sinsp_container_info& container, const libsinsp::cgroup_limits::cgroup_limits_key& key)
{
	runtime::v1alpha2::ContainerStatusRequest req;
	runtime::v1alpha2::ContainerStatusResponse resp;
	req.set_container_id(container.m_id);
	req.set_verbose(true);
	grpc::ClientContext context;
	auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(s_cri_timeout);
	context.set_deadline(deadline);
	grpc::Status status = s_cri->ContainerStatus(&context, req, &resp);

	g_logger.format(sinsp_logger::SEV_DEBUG,
			"cri (%s): Status from ContainerStatus: (%s)",
			container.m_id.c_str(),
			status.error_message().c_str());

	if(!status.ok())
	{
		if(is_pod_sandbox(container.m_id))
		{
			container.m_is_pod_sandbox = true;
			return true;
		}
		g_logger.format(sinsp_logger::SEV_DEBUG, "cri (%s): id is neither a container nor a pod sandbox",
			container.m_id.c_str());
		return false;
	}

	if(!resp.has_status())
	{
		ASSERT(false);
		return false;
	}

	const auto &resp_container = resp.status();
	container.m_name = resp_container.metadata().name();

	for(const auto &pair : resp_container.labels())
	{
		container.m_labels[pair.first] = pair.second;
	}

	parse_cri_image(resp_container, container);
	parse_cri_mounts(resp_container, container);

	if(parse_containerd(resp, container))
	{
		return true;
	}

	libsinsp::cgroup_limits::cgroup_limits_value limits;
	libsinsp::cgroup_limits::get_cgroup_resource_limits(key, limits);

	container.m_memory_limit = limits.m_memory_limit;
	container.m_cpu_shares = limits.m_cpu_shares;
	container.m_cpu_quota = limits.m_cpu_quota;
	container.m_cpu_period = limits.m_cpu_period;

	if(s_cri_extra_queries)
	{
		container.m_container_ip = get_container_ip(container.m_id);
		container.m_imageid = get_container_image_id(resp_container.image_ref());
	}

	return true;
}

void cri_async_source::run_impl()
{
	libsinsp::cgroup_limits::cgroup_limits_key key;

	while (dequeue_next_key(key))
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"cri_async (%s): Source dequeued key",
				key.m_container_id.c_str());

		sinsp_container_info res;

		res.m_lookup_state = sinsp_container_lookup_state::SUCCESSFUL;
		res.m_type = s_cri_runtime_type;
		res.m_id = key.m_container_id;

		if(!parse_cri(res, key))
		{
			g_logger.format(sinsp_logger::SEV_DEBUG,
					"cri_async (%s): Failed to get CRI metadata, returning successful=false",
					key.m_container_id.c_str());
			res.m_lookup_state = sinsp_container_lookup_state::FAILED;
		}

		g_logger.format(sinsp_logger::SEV_DEBUG,
				"cri_async (%s): Parse successful, storing value",
				key.m_container_id.c_str());

		store_value(key, res);
	}

}

bool cri_async_source::lookup_sync(const libsinsp::cgroup_limits::cgroup_limits_key& key,
		 sinsp_container_info& value)
{
	value.m_lookup_state = sinsp_container_lookup_state::SUCCESSFUL;
	value.m_type = s_cri_runtime_type;
	value.m_id = key.m_container_id;

	if(!parse_cri(value, key))
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"cri_async (%s): Failed to get CRI metadata, returning successful=false",
				key.m_container_id.c_str());
		value.m_lookup_state = sinsp_container_lookup_state::FAILED;
	}

	return true;
}

cri::cri()
{
	if(s_cri || s_cri_unix_socket_path.empty()) {
		return;
	}

	auto cri_path = scap_get_host_root() + s_cri_unix_socket_path;
	struct stat s = {};
	if(stat(cri_path.c_str(), &s) != 0 || (s.st_mode & S_IFMT) != S_IFSOCK) {
		return;
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
		return;
	}

	g_logger.format(sinsp_logger::SEV_INFO, "cri: CRI runtime: %s %s", vresp.runtime_name().c_str(), vresp.runtime_version().c_str());
	s_cri_runtime_type = get_cri_runtime_type(vresp.runtime_name());
}

void cri::cleanup()
{
	if(m_async_source)
	{
		m_async_source->quiesce();
	}
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
	s_cri_timeout = timeout_ms + s_cri_lookup_delay_ms;
}

void cri::set_extra_queries(bool extra_queries) {
	s_cri_extra_queries = extra_queries;
}

void cri::set_async(bool async)
{
	s_async = async;
}

void cri::set_cri_delay(uint64_t delay_ms)
{
	s_cri_lookup_delay_ms = delay_ms;
}

bool cri::resolve(sinsp_container_manager* manager, sinsp_threadinfo* tinfo, bool query_os_for_missing_info)
{
	std::string container_id;

	if(!matches_runc_cgroups(tinfo, CRI_CGROUP_LAYOUT, container_id))
	{
		return false;
	}
	tinfo->m_container_id = container_id;

	if(!manager->should_lookup(container_id, s_cri_runtime_type))
	{
		return true;
	}

	auto container = std::make_shared<sinsp_container_info>();
	container->m_id = container_id;
	container->m_type = s_cri_runtime_type;
	if (mesos::set_mesos_task_id(*container, tinfo))
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"cri (%s) Mesos CRI container, Mesos task ID: [%s]",
				container_id.c_str(), container->m_mesos_task_id.c_str());
	}

	if (query_os_for_missing_info)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"cri (%s): Performing lookup",
				container_id.c_str());

		if(!s_cri)
		{
			// This isn't an error in the case where the
			// configured unix domain socket doesn't exist. In
			// that case, s_cri isn't initialized at all. Hence,
			// the DEBUG.
			g_logger.format(sinsp_logger::SEV_DEBUG,
					"cri (%s): Could not parse cri (no s_cri object)",
					container_id.c_str());
			return false;
		}

		container->m_lookup_state = sinsp_container_lookup_state::SUCCESSFUL;
		libsinsp::cgroup_limits::cgroup_limits_key key(
			container->m_id,
			tinfo->get_cgroup("cpu"),
			tinfo->get_cgroup("memory"));

		if(!m_async_source)
		{
			auto async_source = new cri_async_source(manager, s_cri_timeout);
			m_async_source = std::unique_ptr<cri_async_source>(async_source);
		}

		manager->set_lookup_status(container_id, s_cri_runtime_type, sinsp_container_lookup_state::STARTED);
		auto cb = [manager](const libsinsp::cgroup_limits::cgroup_limits_key& key, const sinsp_container_info &res)
		{
			g_logger.format(sinsp_logger::SEV_DEBUG,
					"cri_async (%s): Source callback result=%d",
					key.m_container_id.c_str(),
					res.m_lookup_state);

			manager->notify_new_container(res);
		};

		sinsp_container_info result;

		bool done;
		if(s_async)
		{
			done = m_async_source->lookup_delayed(key, result, chrono::milliseconds(s_cri_lookup_delay_ms), cb);
		}
		else
		{
			done = m_async_source->lookup_sync(key, result);
		}

		if (done)
		{
			// if a previous lookup call already found the metadata, process it now
			cb(key, result);

			if(s_async)
			{
				// This should *never* happen, in async mode as ttl is 0 (never wait)
				g_logger.format(sinsp_logger::SEV_ERROR,
						"cri_async (%s): Unexpected immediate return from cri_async lookup",
						container_id.c_str());

			}
		}
	}
	else
	{
		manager->notify_new_container(*container);
	}
	return true;
}
