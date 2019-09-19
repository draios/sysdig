#pragma once

#include <string>
#include <utility>
#include "async_key_value_source.h"

namespace libsinsp {
namespace cgroup_limits {

/**
 * \brief The key for cgroup value lookup
 *
 * It's effectively a (container_id, cpu_cgroup, mem_cgroup) tuple
 */
struct cgroup_limits_key {
	cgroup_limits_key() :
		m_container_id(""),
		m_cpu_cgroup(""),
		m_mem_cgroup("") {}

	cgroup_limits_key(std::string container_id, std::string cpu_cgroup_dir, std::string mem_cgroup_dir) :
		m_container_id(std::move(container_id)),
		m_cpu_cgroup(std::move(cpu_cgroup_dir)),
		m_mem_cgroup(std::move(mem_cgroup_dir)) {}

	explicit operator const std::string&() const
	{
		return m_container_id;
	}

	std::string m_container_id;
	std::string m_cpu_cgroup;
	std::string m_mem_cgroup;
};

/**
 * \brief The result of an asynchronous cgroup lookup
 *
 * This contains all the cgroup values we read during the asynchronous lookup
 */
struct cgroup_limits_value {
	cgroup_limits_value() :
		m_cpu_shares(0),
		m_cpu_quota(0),
		m_cpu_period(0),
		m_memory_limit(0) {}

	int64_t m_cpu_shares;
	int64_t m_cpu_quota;
	int64_t m_cpu_period;
	int64_t m_memory_limit;
};

/**
 * \brief Read resource limits from cgroups
 * @param key the container to read limits for
 * @param value output value. when the return value is false, specific fields
 *         may or may not have been modified
 * @param name_check if true and the container doesn't use its own cgroups
 *         for mem/cpu, we log a message and we ignore the values.
 *         "Use its own cgroups" means the container id is present in the cgroup
 *         path, which may not be true for all container engines.
 * @return true when all values have been successfully read, false otherwise
 *
 * Note: reading a zero/negative/very large value is considered a failure,
 * because it might mean that resource limits haven't yet been set. Essentially,
 * `false` means "there's real chance the limits could conceivably change
 * in the future", while `true` means we really don't expect them to change
 * any more.
 */
bool get_cgroup_resource_limits(const cgroup_limits_key& key, cgroup_limits_value& value, bool name_check = true);

}
}
