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

#include <tuples.h>

bool ipv6addr::operator==(const ipv6addr &other)
{
	return (m_b[0] == other.m_b[0] &&
		m_b[1] == other.m_b[1] &&
		m_b[2] == other.m_b[2] &&
		m_b[3] == other.m_b[3]);
}

bool ipv6addr::operator!=(const ipv6addr &other)
{
	return !operator==(other);
}

bool ipv6addr::operator==(const ipv6net &other)
{
	return ((m_b[0] & other.m_netmask.m_b[0]) == (other.m_ip.m_b[0] & other.m_netmask.m_b[0]) &&
		(m_b[1] & other.m_netmask.m_b[1]) == (other.m_ip.m_b[1] & other.m_netmask.m_b[1]) &&
		(m_b[2] & other.m_netmask.m_b[2]) == (other.m_ip.m_b[2] & other.m_netmask.m_b[2]) &&
		(m_b[3] & other.m_netmask.m_b[3]) == (other.m_ip.m_b[3] & other.m_netmask.m_b[3]));
}

bool ipv6addr::operator!=(const ipv6net &other)
{
	return !operator==(other);
}
