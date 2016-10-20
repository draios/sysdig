/*
Copyright (C) 2013-2014 Draios inc.

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

#include "sinsp.h"
#include "sinsp_int.h"

sinsp_ipv4_ifinfo::sinsp_ipv4_ifinfo(uint32_t addr, uint32_t netmask, uint32_t bcast, const char* name)
{
	m_addr = addr;
	m_netmask = netmask;
	m_bcast = bcast;
	m_name = name;
}

void sinsp_ipv4_ifinfo::convert_to_string(char * dest, const uint32_t addr)
{
	sprintf(
		dest, 
		"%d.%d.%d.%d", 
		(addr & 0xFF),
		((addr & 0xFF00) >> 8),
		((addr & 0xFF0000) >> 16),
		((addr & 0xFF000000) >> 24));
}

string sinsp_ipv4_ifinfo::address() const
{
	char str_addr[16];
	convert_to_string(str_addr, m_addr);
	return string(str_addr);
}

string sinsp_ipv4_ifinfo::to_string() const
{
	char s[100];
	char str_addr[16];
	char s_netmask[16];
	char s_bcast[16];

	convert_to_string(str_addr, m_addr);
	convert_to_string(s_netmask, m_netmask);
	convert_to_string(s_bcast, m_bcast);
	sprintf(s, "%s inet %s netmask %s broadcast %s", m_name.c_str(), str_addr, s_netmask, s_bcast);
	return string(s);
}

uint32_t sinsp_network_interfaces::infer_ipv4_address(uint32_t destination_address)
{
	vector<sinsp_ipv4_ifinfo>::iterator it;

	// first try to find exact match
	for(it = m_ipv4_interfaces.begin(); it != m_ipv4_interfaces.end(); it++)
	{
		if(it->m_addr == destination_address)
		{
			return it->m_addr;
		}
	}

	// try to find an interface for the same subnet
	for(it = m_ipv4_interfaces.begin(); it != m_ipv4_interfaces.end(); it++)
	{
		if((it->m_addr & it->m_netmask) == (destination_address & it->m_netmask))
		{
			return it->m_addr;
		}
	}

	// otherwise take the first non loopback interface
	for(it = m_ipv4_interfaces.begin(); it != m_ipv4_interfaces.end(); it++)
	{
		if(it->m_addr != LOOPBACK_ADDR)
		{
			return it->m_addr;
		}
	}
	return 0;
}

void sinsp_network_interfaces::update_fd(sinsp_fdinfo_t *fd)
{
	ipv4tuple *pipv4info = &(fd->m_sockinfo.m_ipv4info);

	//
	// only handle ipv4 udp sockets
	//
	if(fd->m_type != SCAP_FD_IPV4_SOCK)
	{
		return;
	}

	if(0 != pipv4info->m_fields.m_sip && 0 != pipv4info->m_fields.m_dip)
	{
		return;
	}
	if(0 == pipv4info->m_fields.m_sip)
	{
		uint32_t newaddr;
		newaddr = infer_ipv4_address(pipv4info->m_fields.m_dip);

		if(newaddr == pipv4info->m_fields.m_dip)
		{
			if(pipv4info->m_fields.m_sport == pipv4info->m_fields.m_dport)
			{
				return;
			}
		}

		pipv4info->m_fields.m_sip = newaddr;
	}
	else
	{
		uint32_t newaddr;
		newaddr = infer_ipv4_address(pipv4info->m_fields.m_sip);

		if(newaddr == pipv4info->m_fields.m_sip)
		{
			if(pipv4info->m_fields.m_sport == pipv4info->m_fields.m_dport)
			{
				return;
			}
		}

		pipv4info->m_fields.m_dip = newaddr;
	}
}

bool sinsp_network_interfaces::is_ipv4addr_in_subnet(uint32_t addr)
{
	vector<sinsp_ipv4_ifinfo>::iterator it;

	//
	// Accept everything that comes from 192.168.0.0/16 or 10.0.0.0/8
	//
	if((addr & 0x000000ff) == 0x0000000a ||
		(addr & 0x0000ffff) == 0x0000a8c0 ||
		(addr & 0x00003fff) == 0x000010ac)
	{
		return true;
	}

	// try to find an interface for the same subnet
	for(it = m_ipv4_interfaces.begin(); it != m_ipv4_interfaces.end(); it++)
	{
		if((it->m_addr & it->m_netmask) == (addr & it->m_netmask))
		{
			return true;
		}
	}

	return false;
}

bool sinsp_network_interfaces::is_ipv4addr_in_local_machine(uint32_t addr, sinsp_threadinfo* tinfo)
{
	if(!tinfo->m_container_id.empty())
	{
		sinsp_container_info container_info;
		bool found = m_inspector->m_container_manager.get_container(tinfo->m_container_id, &container_info);

		//
		// Note: if we don't have container info, any pick we make is arbitrary.
		// To at least achieve consistency across client and server, we just match the host interface addresses. 
		//
		if(found)
		{
			if(container_info.m_container_ip != 0)
			{
				//
				// We have a container info with a valid container IP. Let's use it.
				//
				if(addr == container_info.m_container_ip)
				{
					return true;
				}
			}
			else
			{
				//
				// Container info is valid, but the IP address is zero.
				// This happens for example in the case of kubernetes pods, where we are
				// typically unable to get the address for one of the containers in the pod.
				// In that case, the address can be fetched from another of the containers
				// in the pod, so we scan the list looking for matches. If no match is found,
				// We just jump to checking the host interfaces.
				//
				const unordered_map<string, sinsp_container_info>* clist = m_inspector->m_container_manager.get_containers();

				for(auto it = clist->begin(); it != clist->end(); ++it)
				{
					if(it->second.m_container_ip == addr)
					{
						return true;
					}
				}
			}
		}
	}

	vector<sinsp_ipv4_ifinfo>::iterator it;

	// try to find an interface that has the given IP as address
	for(it = m_ipv4_interfaces.begin(); it != m_ipv4_interfaces.end(); it++)
	{
		if(it->m_addr == addr)
		{
			return true;
		}
	}

	return false;
}

void sinsp_network_interfaces::import_ipv4_ifaddr_list(uint32_t count, scap_ifinfo_ipv4* plist)
{
	if (count == 0)
	{
		return;
	}
	for(uint32_t j = 0; j < count; j++)
	{
		sinsp_ipv4_ifinfo info;
		info.m_addr = plist->addr;
		info.m_netmask = plist->netmask;
		info.m_bcast = plist->bcast;
		info.m_name = plist->ifname;
		m_ipv4_interfaces.push_back(info);
		plist++;
	}
}

void sinsp_network_interfaces::import_ipv6_ifaddr_list(uint32_t count, scap_ifinfo_ipv6* plist)
{
	if (count == 0)
	{
		return;
	}
	for(uint32_t j = 0; j < count; j++)
	{
		sinsp_ipv6_ifinfo info;
		memcpy(info.m_addr, plist->addr, SCAP_IPV6_ADDR_LEN);
		memcpy(info.m_netmask, plist->netmask, SCAP_IPV6_ADDR_LEN);
		memcpy(info.m_bcast, plist->bcast, SCAP_IPV6_ADDR_LEN);
		info.m_name = plist->ifname;
		m_ipv6_interfaces.push_back(info);
		plist++;
	}
}

void sinsp_network_interfaces::import_interfaces(scap_addrlist* paddrlist)
{
	if(NULL != paddrlist)
	{
		clear();
		import_ipv4_ifaddr_list(paddrlist->n_v4_addrs, paddrlist->v4list);
		import_ipv6_ifaddr_list(paddrlist->n_v6_addrs, paddrlist->v6list);
	}
}

void sinsp_network_interfaces::import_ipv4_interface(const sinsp_ipv4_ifinfo& ifinfo)
{
	m_ipv4_interfaces.push_back(ifinfo);
}

vector<sinsp_ipv4_ifinfo>* sinsp_network_interfaces::get_ipv4_list()
{
	return &m_ipv4_interfaces;
}

vector<sinsp_ipv6_ifinfo>* sinsp_network_interfaces::get_ipv6_list()
{
	return &m_ipv6_interfaces;
}
