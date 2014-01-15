#pragma once

//
// An IPv4 tuple
//
typedef union _ipv4tuple
{
	struct 
	{
		uint32_t m_sip;
		uint32_t m_dip;
		uint16_t m_sport;
		uint16_t m_dport;
		uint8_t m_l4proto;
	}m_fields;
	uint8_t m_all[13];
}ipv4tuple;

typedef union _ipv6tuple
{
	struct
	{
		uint32_t m_sip[4];
		uint32_t m_dip[4];
		uint16_t m_sport;
		uint16_t m_dport;
		uint8_t m_l4proto;
	} m_fields;
} ipv6tuple;

//
// A Unix tuple
//
typedef union _unix_tuple
{
	struct
	{
		uint64_t m_source;
		uint64_t m_dest;
	} m_fields;
	uint8_t m_all[16];
} unix_tuple;
