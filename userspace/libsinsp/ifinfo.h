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

#pragma once

#define LOOPBACK_ADDR 0x0100007f

#ifndef VISIBILITY_PRIVATE
#define VISIBILITY_PRIVATE private:
#endif

//
// network interface info ipv4
//
class SINSP_PUBLIC sinsp_ipv4_ifinfo
{
public:
	sinsp_ipv4_ifinfo() {};

	sinsp_ipv4_ifinfo(uint32_t addr, uint32_t netmask, uint32_t bcast, const char* name);

	string to_string() const;
	string address() const;

	uint32_t m_addr;
	uint32_t m_netmask;
	uint32_t m_bcast;
	string m_name;
private:
	static void convert_to_string(char * dest, const uint32_t addr);
};

//
// network interface info ipv6
//
class SINSP_PUBLIC sinsp_ipv6_ifinfo
{
public:
	sinsp_ipv6_ifinfo() {};

	char m_addr[SCAP_IPV6_ADDR_LEN];
	char m_netmask[SCAP_IPV6_ADDR_LEN];
	char m_bcast[SCAP_IPV6_ADDR_LEN];

	string m_name;
};

class SINSP_PUBLIC sinsp_network_interfaces
{
public:
	sinsp_network_interfaces(sinsp* inspector): m_inspector(inspector)
	{
	}

	void import_interfaces(scap_addrlist* paddrlist);
	void import_ipv4_interface(const sinsp_ipv4_ifinfo& ifinfo);
	void update_fd(sinsp_fdinfo_t *fd);
	bool is_ipv4addr_in_subnet(uint32_t addr);
	bool is_ipv4addr_in_local_machine(uint32_t addr, sinsp_threadinfo* tinfo);
	vector<sinsp_ipv4_ifinfo>* get_ipv4_list();
	vector<sinsp_ipv6_ifinfo>* get_ipv6_list();
	inline void clear();

VISIBILITY_PRIVATE
	uint32_t infer_ipv4_address(uint32_t destination_address);
	void import_ipv4_ifaddr_list(uint32_t count, scap_ifinfo_ipv4* plist);
	void import_ipv6_ifaddr_list(uint32_t count, scap_ifinfo_ipv6* plist);
	vector<sinsp_ipv4_ifinfo> m_ipv4_interfaces;
	vector<sinsp_ipv6_ifinfo> m_ipv6_interfaces;
	sinsp* m_inspector;
};

void sinsp_network_interfaces::clear()
{
	m_ipv4_interfaces.clear();
	m_ipv6_interfaces.clear();
}