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

/** @defgroup state State management 
 *  @{
 */

/*!
	\brief An IPv4 tuple. 
*/
typedef union _ipv4tuple
{
	struct 
	{
		uint32_t m_sip; ///< Source (i.e. client) address. 
		uint32_t m_dip; ///< Destination (i.e. server) address.
		uint16_t m_sport; ///< Source (i.e. client) port.
		uint16_t m_dport; ///< Destination (i.e. server) port.
		uint8_t m_l4proto; ///< Layer 4 protocol (e.g. TCP, UDP...).
	}m_fields;
	uint8_t m_all[13]; ///< The fields as a raw array ob bytes. Used for hasing.
}ipv4tuple;

/*!
	\brief An IPv4 network.
*/
typedef struct ipv4net
{
	uint32_t m_ip; ///< IP addr
	uint32_t m_netmask; ///< Subnet mask
}ipv4net;

/*!
	\brief An IPv6 tuple. 
*/
typedef union _ipv6tuple
{
	struct
	{
		uint32_t m_sip[4]; ///< source (i.e. client) address.
		uint32_t m_dip[4]; ///< destination (i.e. server) address.
		uint16_t m_sport; ///< source (i.e. client) port.
		uint16_t m_dport; ///< destination (i.e. server) port.
		uint8_t m_l4proto; ///< Layer 4 protocol (e.g. TCP, UDP...)
	} m_fields;
	uint8_t m_all[37]; ///< The fields as a raw array ob bytes. Used for hasing.
} ipv6tuple;

/*!
	\brief An IPv4 server address. 
*/
typedef struct ipv4serverinfo
{
	uint32_t m_ip; ///< address
	uint16_t m_port; ///< port
	uint8_t m_l4proto; ///< IP protocol
} ipv4serverinfo;

/*!
	\brief An IPv6 server address. 
*/
typedef struct ipv6serverinfo
{
	uint32_t m_ip[4];  ///< address
	uint16_t m_port;  ///< port
	uint8_t m_l4proto;  ///< IP protocol
} ipv6serverinfo;

/*!
	\brief A unix socket tuple. 
*/
typedef union _unix_tuple
{
	struct
	{
		uint64_t m_source;  ///< source OS pointer.
		uint64_t m_dest;  ///< destination OS pointer.
	} m_fields;
	uint8_t m_all[16]; ///< The fields as a raw array ob bytes. Used for hasing.
} unix_tuple;

/*@}*/
