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

ipv6addr ipv6addr::empty_address = {0x00000000, 0x00000000, 0x00000000, 0x00000000};

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

bool ipv6addr::in_subnet(const ipv6addr &other)
{
	// They're in the same subnet if the first 64 bits match
	// (Assumes convention of first 48 bits for network, next 16
	// bits for subnet).
	return (m_b[0] == other.m_b[0] &&
		m_b[1] == other.m_b[1]);
}
