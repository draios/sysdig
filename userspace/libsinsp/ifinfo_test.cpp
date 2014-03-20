/*
Copyright (C) 2013-2014 Draios inc.
 
This file is part of sysdig.

sysdig is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

sysdig is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with sysdig.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <gtest.h>
#define VISIBILITY_PRIVATE
#include "sinsp.h"
#include "sinsp_int.h"
#include "ifinfo.h"


uint32_t parse_ipv4_addr(const char *dotted_notation)
{
	uint32_t a, b, c, d;
	sscanf(dotted_notation, "%d.%d.%d.%d", &a, &b, &c, &d);
	return d << 24 | c << 16 | b << 8 | a;
}

uint32_t parse_ipv4_netmask(const char *dotted_notation)
{
	return parse_ipv4_addr(dotted_notation);
}

uint32_t parse_ipv4_broadcast(const char *dotted_notation)
{
	return parse_ipv4_addr(dotted_notation);
}

sinsp_ipv4_ifinfo make_ipv4_interface(const char *addr, const char *netmask, const char* broadcast, const char *name)
{
	return sinsp_ipv4_ifinfo(
	           parse_ipv4_addr(addr),
	           parse_ipv4_netmask(netmask),
	           parse_ipv4_broadcast(broadcast),
	           name);
}

sinsp_ipv4_ifinfo make_ipv4_localhost()
{
	return make_ipv4_interface("127.0.0.1", "255.0.0.0", "127.0.0.1", "lo");
}


void convert_to_string(char* dest, uint32_t addr)
{
	sprintf(
		dest, 
		"%d.%d.%d.%d", 
		(addr & 0xFF),
		((addr & 0xFF00) >> 8),
		((addr & 0xFF0000) >> 16),
		((addr & 0xFF000000) >> 24));
}



#define EXPECT_ADDR_EQ(dotted_notation,addr) {\
	char buf[17];\
	convert_to_string(buf,addr);\
	EXPECT_STREQ(dotted_notation,buf);\
};

TEST(sinsp_network_interfaces, fd_is_of_wrong_type)
{
	sinsp_fdinfo fd;
	fd.m_type = SCAP_FD_UNKNOWN;
	sinsp_network_interfaces interfaces;
	interfaces.update_fd(&fd);
}

TEST(sinsp_network_interfaces, socket_is_of_wrong_type)
{
	sinsp_fdinfo fd;
	fd.m_type = SCAP_FD_IPV4_SOCK;
	fd.m_info.m_ipv4info.m_fields.m_l4proto = SCAP_L4_TCP;
	sinsp_network_interfaces interfaces;
	interfaces.update_fd(&fd);
}

TEST(sinsp_network_interfaces, sip_and_dip_are_not_zero)
{
	sinsp_fdinfo fd;
	fd.m_type = SCAP_FD_IPV4_SOCK;
	fd.m_info.m_ipv4info.m_fields.m_l4proto = SCAP_L4_UDP;
	fd.m_info.m_ipv4info.m_fields.m_sip = 1;
	fd.m_info.m_ipv4info.m_fields.m_dip = 1;
	sinsp_network_interfaces interfaces;
	interfaces.update_fd(&fd);
}

TEST(sinsp_network_interfaces, infer_finds_exact_match)
{
	sinsp_network_interfaces interfaces;
	interfaces.m_ipv4_interfaces.push_back(make_ipv4_localhost());
	interfaces.m_ipv4_interfaces.push_back(make_ipv4_interface("192.168.22.149", "255.255.255.0", "192.168.22.255", "eth0"));
	EXPECT_ADDR_EQ("127.0.0.1",interfaces.infer_ipv4_address(parse_ipv4_addr("127.0.0.1")));
	EXPECT_ADDR_EQ("192.168.22.149",interfaces.infer_ipv4_address(parse_ipv4_addr("192.168.22.149")));
}

TEST(sinsp_network_interfaces, infer_finds_same_subnet)
{
	sinsp_network_interfaces interfaces;
	interfaces.m_ipv4_interfaces.push_back(make_ipv4_localhost());
	interfaces.m_ipv4_interfaces.push_back(make_ipv4_interface("192.168.22.149", "255.255.255.0", "192.168.22.255", "eth0"));
	EXPECT_ADDR_EQ("192.168.22.149",interfaces.infer_ipv4_address(parse_ipv4_addr("192.168.22.11")));
}

TEST(sinsp_network_interfaces, infer_defaults_to_first_non_loopback)
{
	sinsp_network_interfaces interfaces;
	interfaces.m_ipv4_interfaces.push_back(make_ipv4_localhost());
	interfaces.m_ipv4_interfaces.push_back(make_ipv4_interface("192.168.22.149", "255.255.255.0", "192.168.22.255", "eth0"));
	interfaces.m_ipv4_interfaces.push_back(make_ipv4_interface("192.168.22.150", "255.255.255.0", "192.168.22.255", "eth1"));
	EXPECT_ADDR_EQ("192.168.22.149",interfaces.infer_ipv4_address(parse_ipv4_addr("193.168.22.11")));
}