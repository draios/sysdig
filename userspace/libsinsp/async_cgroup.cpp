#include "async_cgroup.h"

#include <fstream>
#include "sinsp.h"

namespace {
// to prevent 32-bit number of kilobytes from overflowing, ignore values larger than 4 TiB.
// This reports extremely large values (e.g. almost-but-not-quite 9EiB as set by k8s) as unlimited.
// Note: we use the same maximum value for cpu shares/quotas as well; the typical values are much lower
// and so should never exceed CGROUP_VAL_MAX either
constexpr const int64_t CGROUP_VAL_MAX = (1UL << 42u) - 1;

/**
 * \brief Read a single int64_t value from cgroupfs
 * @param subsys path to the specific cgroup subsystem, e.g. /sys/fs/cgroup/cpu
 * @param cgroup cgroup path within the cgroup mountpoint (like in /proc/pid/cgroup)
 * @param filename the filename within the cgroup directory, e.g. cpu.shares
 * @param out reference to the output value
 * @return true if we successfully read the value and it's within reasonable range,
 *          reasonable being [0; CGROUP_VAL_MAX)
 */
bool read_cgroup_val(std::shared_ptr<std::string>& subsys,
	const std::string& cgroup, const std::string& filename, int64_t& out)
{
	std::string path = *subsys.get() + "/" + cgroup + "/" + filename;
	std::ifstream cg_val(path);

	int64_t val = -1;
	cg_val >> val;

	if(val <= 0 || val > CGROUP_VAL_MAX)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "(async-cg) value of %s (%lld) out of range, ignoring",
			path.c_str(), val);
		return false;
	}
	out = val;
	return true;
}
}

namespace libsinsp {
namespace async_cgroup {

bool get_cgroup_resource_limits(const delayed_cgroup_key& key, delayed_cgroup_value& value, bool report_no_cgroup)
{
	bool found_all = true;
	auto no_cg_log_level = report_no_cgroup
		? sinsp_logger::SEV_INFO
		: sinsp_logger::SEV_DEBUG;

	std::shared_ptr<std::string> memcg_root = sinsp::lookup_cgroup_dir("memory");
	if(key.m_mem_cgroup.find(key.m_container_id) == std::string::npos)
	{
		g_logger.format(no_cg_log_level, "(async-cg) mem cgroup for container [%s]: %s/%s -- no per-container memory cgroup, ignoring",
			key.m_container_id.c_str(), memcg_root->c_str(), key.m_mem_cgroup.c_str());
	}
	else
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "(async-cg) mem cgroup for container [%s]: %s/%s",
			key.m_container_id.c_str(), memcg_root->c_str(), key.m_mem_cgroup.c_str());
		found_all = read_cgroup_val(memcg_root, key.m_mem_cgroup, "memory.limit_in_bytes", value.m_memory_limit) && found_all;
	}

	std::shared_ptr<std::string> cpucg_root = sinsp::lookup_cgroup_dir("cpu");
	if(key.m_cpu_cgroup.find(key.m_container_id) == std::string::npos)
	{
		g_logger.format(no_cg_log_level, "(async-cg) cpu cgroup for container [%s]: %s/%s -- no per-container CPU cgroup, ignoring",
				key.m_container_id.c_str(), cpucg_root->c_str(), key.m_cpu_cgroup.c_str());
	}
	else
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "(async-cg) cpu cgroup for container [%s]: %s/%s",
				key.m_container_id.c_str(), cpucg_root->c_str(), key.m_cpu_cgroup.c_str());
		found_all = read_cgroup_val(cpucg_root, key.m_cpu_cgroup, "cpu.shares", value.m_cpu_shares) && found_all;
		found_all = read_cgroup_val(cpucg_root, key.m_cpu_cgroup, "cpu.cfs_quota_us", value.m_cpu_quota) && found_all;
		found_all = read_cgroup_val(cpucg_root, key.m_cpu_cgroup, "cpu.cfs_period_us", value.m_cpu_period) && found_all;
	}

	g_logger.format(sinsp_logger::SEV_DEBUG,
		"(async-cg) Got cgroup limits for container [%s]: "
		"mem_limit=%ld, cpu_shares=%ld cpu_quota=%ld cpu_period=%ld",
		key.m_container_id.c_str(),
		value.m_memory_limit, value.m_cpu_shares, value.m_cpu_quota, value.m_cpu_period);

	return found_all;
}

void delayed_cgroup_lookup::run_impl()
{
	delayed_cgroup_key key;
	while(dequeue_next_key(key)) {
		delayed_cgroup_value value;
		get_cgroup_resource_limits(key, value, false);
		store_value(key, value);
	}
}

void delayed_cgroup_lookup::update(sinsp_container_manager* manager, const delayed_cgroup_key& key, const delayed_cgroup_value& value)
{
	auto container = manager->get_container(key.m_container_id);
	if(container)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"(async-cg) Storing limits for container [%s]: "
				"mem_limit=%ld, cpu_shares=%ld, cpu_quota=%ld, cpu_period=%ld",
				key.m_container_id.c_str(),
				value.m_memory_limit, value.m_cpu_shares,
				value.m_cpu_quota, value.m_cpu_period);
		container->m_memory_limit = value.m_memory_limit;
		container->m_cpu_shares = value.m_cpu_shares;
		container->m_cpu_quota = value.m_cpu_quota;
		container->m_cpu_period = value.m_cpu_period;
	}
	else
	{
		g_logger.format(sinsp_logger::SEV_NOTICE,
				"(async-cg) Dropping limits for already gone container [%s]: "
				"mem_limit=%ld, cpu_shares=%ld, cpu_quota=%ld, cpu_period=%ld",
				key.m_container_id.c_str(),
				value.m_memory_limit, value.m_cpu_shares,
				value.m_cpu_quota, value.m_cpu_period);
	}
}
}
}
