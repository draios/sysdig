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

#include <string>
#include <stdint.h>
#include <async_cgroup.h>
#include <async_container.h>

class sinsp_container_manager;
class sinsp_threadinfo;

#include "container_engine/container_engine.h"

namespace runtime {
namespace v1alpha2 {
class ContainerStatusResponse;
}
}

namespace libsinsp {
namespace container_engine {

/**
 * Asynchronous metadata lookup for CRI containers
 *
 * There are two related async data sources:
 * 1. `cri_async_source`, which is responsible for doing the actual gRPC calls
 * to the CRI API. This happens by executing synchronous gRPC requests
 * in a separate thread. The execution happens (as close as possible to)
 * immediately after matching the cgroup. This source is owned by the resolver
 * object.
 *
 * 2. We only get resource limits (CPU, memory) from containerd, so for other
 * runtimes we need to read them directly from cgroups. This is race-prone
 * as the runtime might not be done with setting up the limits by the time
 * we see the new process, so (if not all limits are set to reasonable values)
 * we repeat the read after CGROUP_LOOKUP_DELAY_MS milliseconds, which should
 * give the runtime enough time to set up the cgroups.
 */
class cri_async_source : public sysdig::async_container_source<libsinsp::async_cgroup::delayed_cgroup_key> {

	// how long do we wait
	static constexpr const uint64_t CGROUP_LOOKUP_DELAY_MS = 1000;

	// how long do we wait on cgroup lookup result before giving up
	// Note: this value includes the initial delay
	static constexpr const uint64_t CGROUP_MAX_DELAY_MS = 2000;

public:
	explicit cri_async_source(sinsp_container_manager* manager, uint64_t ttl_ms) :
		async_container_source(NO_WAIT_LOOKUP, ttl_ms),
		m_async_cgroups(NO_WAIT_LOOKUP, CGROUP_MAX_DELAY_MS),
		m_container_manager(manager)
	{
	}

	void quiesce() override {
		m_async_cgroups.quiesce();
		async_container_source::stop();
	}

	bool parse_cri(sinsp_container_info *container, const libsinsp::async_cgroup::delayed_cgroup_key& key);
private:
	bool parse_containerd(const runtime::v1alpha2::ContainerStatusResponse& status, sinsp_container_info *container);
	void run_impl() override;

	libsinsp::async_cgroup::delayed_cgroup_lookup m_async_cgroups;
	sinsp_container_manager* m_container_manager;
};

class cri : public resolver
{
public:
	using resolver::resolver;
	bool resolve(sinsp_container_manager* manager, sinsp_threadinfo* tinfo, bool query_os_for_missing_info) override;
	void cleanup() override;
	static void set_cri_socket_path(const std::string& path);
	static void set_cri_timeout(int64_t timeout_ms);
	static void set_extra_queries(bool extra_queries);
	static void set_async(bool async);
	static void set_async_limits(bool async_limits);

private:
	std::unique_ptr<cri_async_source> m_cri_info_source;
};
}
}
