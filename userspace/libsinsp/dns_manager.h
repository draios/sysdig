/*
Copyright (C) 2013-2018 Draios inc.

This file is part of sysdig.

sysdig is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.

sysdig is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with sysdig.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string>
#include <thread>
#include <chrono>
#include <future>
#include <mutex>
#ifdef HAS_CAPTURE
#include "tbb/concurrent_unordered_map.h"
#endif
#include "sinsp.h"


struct sinsp_dns_resolver
{
	static void refresh(uint64_t erase_timeout, uint64_t base_refresh_timeout, uint64_t max_refresh_timeout, std::future<void> f_exit);
};

class sinsp_dns_manager
{
public:

	bool match(const char *name, int af, void *addr, uint64_t ts);
	string name_of(int af, void *addr);

	void cleanup();

        static sinsp_dns_manager& get()
        {
            static sinsp_dns_manager instance;
            return instance;
        };

	void set_erase_timeout(uint64_t ns)
	{
		m_erase_timeout = ns;
	};
	void set_base_refresh_timeout(uint64_t ns)
	{
		m_base_refresh_timeout = ns;
	};
	void set_max_refresh_timeout(uint64_t ns)
	{
		m_max_refresh_timeout = ns;
	};

	size_t size()
	{
#ifdef HAS_CAPTURE
		return m_cache.size();
#else
		return 0;
#endif
	};

private:

	sinsp_dns_manager() :
		m_erase_timeout(3600 * ONE_SECOND_IN_NS),
		m_base_refresh_timeout(10 * ONE_SECOND_IN_NS),
		m_max_refresh_timeout(320 * ONE_SECOND_IN_NS)
	{};
        sinsp_dns_manager(sinsp_dns_manager const&) = delete;
        void operator=(sinsp_dns_manager const&) = delete;

#ifdef HAS_CAPTURE
	struct dns_info
	{
		bool operator==(const dns_info &other) const
		{
			return m_v4_addrs == other.m_v4_addrs && m_v6_addrs == other.m_v6_addrs;
		};
		bool operator!=(const dns_info &other) const
		{
			return !operator==(other);
		};

		uint64_t m_timeout;
		uint64_t m_last_resolve_ts;
		uint64_t m_last_used_ts;
		std::set<uint32_t> m_v4_addrs;
		std::set<ipv6addr> m_v6_addrs;
	};

	static inline dns_info resolve(const std::string &name, uint64_t ts);

	typedef tbb::concurrent_unordered_map<std::string, dns_info> c_dns_table;
	c_dns_table m_cache;
#endif

	// tbb concurrent unordered map is not thread-safe for deletions,
	// so we still need a mutex, but the chances of waiting are really
	// low, since we will almost never do an erase.
	std::mutex m_erase_mutex;

	// used to let m_resolver when to terminate
	std::promise<void> m_exit_signal;

	std::thread *m_resolver;

	uint64_t m_erase_timeout;
	uint64_t m_base_refresh_timeout;
	uint64_t m_max_refresh_timeout;

	friend sinsp_dns_resolver;
};
