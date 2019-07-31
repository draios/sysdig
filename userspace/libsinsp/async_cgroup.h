#pragma once

#include <string>
#include <utility>
#include "async_key_value_source.h"

class sinsp_container_manager;

namespace {
bool less_than(const std::string& lhs, const std::string& rhs, bool if_equal=false)
{
	int cmp = lhs.compare(rhs);
	if(cmp < 0)
	{
		return true;
	}
	else if(cmp > 0)
	{
		return false;
	}
	else
	{
		return if_equal;
	}
}
}

namespace libsinsp {
namespace async_cgroup {

/**
 * \brief The key for asynchronous cgroup value lookup
 *
 * It's effectively a (container_id, cpu_cgroup, mem_cgroup) tuple
 * that can be used as a hash key.
 */
struct delayed_cgroup_key {
	delayed_cgroup_key():
		m_container_id(""),
		m_cpu_cgroup(""),
		m_mem_cgroup("") {}

	delayed_cgroup_key(std::string container_id, std::string cpu_cgroup_dir, std::string mem_cgroup_dir):
		m_container_id(std::move(container_id)),
		m_cpu_cgroup(std::move(cpu_cgroup_dir)),
		m_mem_cgroup(std::move(mem_cgroup_dir)) {}

	bool operator<(const delayed_cgroup_key& rhs) const
	{
		return less_than(m_container_id, rhs.m_container_id,
			less_than(m_cpu_cgroup, rhs.m_cpu_cgroup,
				less_than(m_mem_cgroup, rhs.m_mem_cgroup)));
	}

	bool operator==(const delayed_cgroup_key& rhs) const
	{
		return m_container_id == rhs.m_container_id &&
			m_cpu_cgroup == rhs.m_cpu_cgroup &&
			m_mem_cgroup == rhs.m_mem_cgroup;
	}

	explicit operator const std::string&() const {
		return m_container_id;
	}

	std::string m_container_id; // TODO a shared_ptr would be nice
	std::string m_cpu_cgroup;
	std::string m_mem_cgroup;
};

/**
 * \brief The result of an asynchronous cgroup lookup
 *
 * This contains all the cgroup values we read during the asynchronous lookup
 */
struct delayed_cgroup_value {
	delayed_cgroup_value():
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
 * @param report_no_cgroup if true, log a message when the container doesn't
 *         use its own cgroups for mem/cpu and we ignore the values.
 *         We want to log this only once since the cgroups will stay the same
 *         during subsequent lookups
 * @return true when all values have been successfully read, false otherwise
 *
 * Note: reading a zero/negative/very large value is considered a failure,
 * because it might mean that resource limits haven't yet been set. Essentially,
 * `false` means "there's real chance the limits could conceivably change
 * in the future", while `true` means we really don't expect them to change
 * any more.
 */
bool get_cgroup_resource_limits(const delayed_cgroup_key& key, delayed_cgroup_value& value, bool report_no_cgroup=true);

/**
 * \brief Asynchronous key-value source for delayed cgroup lookups
 *
 * Reading cgroup values immediately after we notice a new container may catch
 * the cgroups before the limits have been set. To give the container runtime
 * more time to set up the resource limits, we delay the cgroup query a bit.
 *
 */
class delayed_cgroup_lookup : public sysdig::async_key_value_source<delayed_cgroup_key, delayed_cgroup_value> {
public:
	using sysdig::async_key_value_source<delayed_cgroup_key, delayed_cgroup_value>::async_key_value_source;

	/**
	 * \brief Store found values in container_manager
	 * @param manager the container manager instance that holds
	 * the containers we're looking up
	 * @param key container lookup key
	 * @param value resource limits found in cgroups
	 *
	 * This method copies any newly found resource limits from the lookup
	 * results back to the container manager.
	 */
	static void update(sinsp_container_manager* manager, const delayed_cgroup_key& key, const delayed_cgroup_value& value);

	/**
	 * \brief Wait for all pending lookups to complete
	 */
	void quiesce() {
		this->stop();
	}
private:
	void run_impl() override;
};
}
}

namespace std {
/**
 * \brief Specialization of std::hash for delayed_cgroup_key
 *
 * It allows `delayed_cgroup_key` instances to be used as `unordered_map` keys
 */
template<> struct hash<libsinsp::async_cgroup::delayed_cgroup_key> {
	std::size_t operator()(const libsinsp::async_cgroup::delayed_cgroup_key& h) const {
		size_t h1 = ::std::hash<std::string>{}(h.m_container_id);
		size_t h2 = ::std::hash<std::string>{}(h.m_cpu_cgroup);
		size_t h3 = ::std::hash<std::string>{}(h.m_mem_cgroup);
		return h1 ^ (h2 << 1u) ^ (h3 << 2u);
	}
};
}
