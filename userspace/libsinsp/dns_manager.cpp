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

#include "dns_manager.h"

void sinsp_dns_resolver::refresh(uint64_t erase_timeout, uint64_t base_refresh_timeout, uint64_t max_refresh_timeout, std::future<void> f_exit)
{
#ifdef HAS_CAPTURE
	sinsp_dns_manager &manager = sinsp_dns_manager::get();
	while(true)
	{
		if(!manager.m_cache.empty())
		{
			std::list<std::string> to_delete;

			uint64_t ts = sinsp_utils::get_current_time_ns();

			for(auto &it: manager.m_cache)
			{
				const std::string &name = it.first;
				sinsp_dns_manager::dns_info &info = it.second;

				if((ts > info.m_last_used_ts) &&
				   (ts - info.m_last_used_ts) > erase_timeout)
				{
					// remove the entry if it's hasn't been used for a whole hour
					to_delete.push_back(name);
				}
				else if(ts > (info.m_last_resolve_ts + info.m_timeout))
				{
					sinsp_dns_manager::dns_info refreshed_info = manager.resolve(name, ts);
					refreshed_info.m_timeout = base_refresh_timeout;
					refreshed_info.m_last_resolve_ts = info.m_last_resolve_ts = ts;

					if(refreshed_info != info)
					{
						info = refreshed_info;
					}
					else if(info.m_timeout < max_refresh_timeout)
					{
						// double the timeout until 320 secs
						info.m_timeout <<= 1;
					}
				}
			}
			if(!to_delete.empty())
			{
				manager.m_erase_mutex.lock();
				for(const auto &name : to_delete)
				{
					manager.m_cache.unsafe_erase(name);
				}
				manager.m_erase_mutex.unlock();
			}
		}

		if(f_exit.wait_for(std::chrono::nanoseconds(base_refresh_timeout)) == std::future_status::ready)
		{
			break;
		}
	}
#endif
}

#ifdef HAS_CAPTURE
inline sinsp_dns_manager::dns_info sinsp_dns_manager::resolve(const std::string &name, uint64_t ts)
{
	dns_info dinfo;

	struct addrinfo hints, *result, *rp;
	memset(&hints, 0, sizeof(struct addrinfo));

	// Allow IPv4 or IPv6, all socket types, all protocols
	hints.ai_family = AF_UNSPEC;

	int s = getaddrinfo(name.c_str(), NULL, &hints, &result);
	if (!s && result)
	{
		for (rp = result; rp != NULL; rp = rp->ai_next)
		{
			if(rp->ai_family == AF_INET)
			{
				dinfo.m_v4_addrs.insert(((struct sockaddr_in*)rp->ai_addr)->sin_addr.s_addr);
			}
			else // AF_INET6
			{
				ipv6addr v6;
				memcpy(v6.m_b, ((struct sockaddr_in6*)rp->ai_addr)->sin6_addr.s6_addr, sizeof(ipv6addr));
				dinfo.m_v6_addrs.insert(v6);
			}
		}
		freeaddrinfo(result);
	}
	return dinfo;
}
#endif

bool sinsp_dns_manager::match(const char *name, int af, void *addr, uint64_t ts)
{
#ifdef HAS_CAPTURE
	if(!m_resolver)
	{
		m_resolver = new thread(sinsp_dns_resolver::refresh, m_erase_timeout, m_base_refresh_timeout, m_max_refresh_timeout, m_exit_signal.get_future());
	}

	string sname = string(name);

	m_erase_mutex.lock();

	if(m_cache.find(sname) == m_cache.end())
	{
		dns_info dinfo = resolve(sname, ts);
		dinfo.m_timeout = m_base_refresh_timeout;
		dinfo.m_last_resolve_ts = ts;
		m_cache[sname] = dinfo;
	}

	m_cache[sname].m_last_used_ts = ts;
	dns_info &dinfo = m_cache[sname];

	m_erase_mutex.unlock();

	if(af == AF_INET6)
	{
		ipv6addr v6;
		memcpy(v6.m_b, addr, sizeof(ipv6addr));
		return dinfo.m_v6_addrs.find(v6) != dinfo.m_v6_addrs.end();
	}
	else if(af == AF_INET)
	{
		return dinfo.m_v4_addrs.find(*(uint32_t *)addr) != dinfo.m_v4_addrs.end();
	}
#endif
	return false;
}

string sinsp_dns_manager::name_of(int af, void *addr)
{
	string ret;

#ifdef HAS_CAPTURE

	if(!m_cache.empty())
	{
		m_erase_mutex.lock();
		for(auto &it: m_cache)
		{
			const std::string &name = it.first;
			sinsp_dns_manager::dns_info &info = it.second;

			if(af == AF_INET6)
			{
				ipv6addr v6;
				memcpy(v6.m_b, addr, sizeof(ipv6addr));
				if (info.m_v6_addrs.find(v6) != info.m_v6_addrs.end())
				{
					ret = name;
					break;
				}
			}
			else if(af == AF_INET && info.m_v4_addrs.find(*(uint32_t *)addr) != info.m_v4_addrs.end())
			{
				ret = name;
				break;
			}
		}
		m_erase_mutex.unlock();
	}
#endif
	return ret;
}

void sinsp_dns_manager::cleanup()
{
	if(m_resolver)
	{
		m_exit_signal.set_value();
		m_resolver->join();
	}
}
