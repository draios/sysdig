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

//
// Why isn't this parser written using antlr or some other parser generator?
// Essentially, after dealing with that stuff multiple times in the past, and fighting for a day
// to configure everything with crappy documentation and code that doesn't compile,
// I decided that I agree with this http://mortoray.com/2012/07/20/why-i-dont-use-a-parser-generator/
// and that I'm going with a manually written parser. The grammar is simple enough that it's not
// going to take more time. On the other hand I will avoid a crappy dependency that breaks my
// code at every new release, and I will have a cleaner and easier to understand code base.
//

#ifdef _WIN32
#define NOMINMAX
#endif

#include <regex>

#include "sinsp.h"
#include "sinsp_int.h"
#include "utils.h"

#ifdef HAS_FILTERING
#include "filter.h"
#include "filterchecks.h"
#include "value_parser.h"
#ifndef _WIN32
#include "arpa/inet.h"
#endif

#ifndef _GNU_SOURCE
//
// Fallback implementation of memmem
//
void *memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen);
#endif

#ifdef _WIN32
#pragma comment(lib, "Ws2_32.lib")
#include <WinSock2.h>
#else
#include <netdb.h>
#endif


extern sinsp_filter_check_list g_filterlist;

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check_list implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_filter_check_list::sinsp_filter_check_list()
{
	//////////////////////////////////////////////////////////////////////////////
	// ADD NEW FILTER CHECK CLASSES HERE
	//////////////////////////////////////////////////////////////////////////////
	add_filter_check(new sinsp_filter_check_fd());
	add_filter_check(new sinsp_filter_check_thread());
	add_filter_check(new sinsp_filter_check_event());
	add_filter_check(new sinsp_filter_check_user());
	add_filter_check(new sinsp_filter_check_group());
	add_filter_check(new sinsp_filter_check_syslog());
	add_filter_check(new sinsp_filter_check_container());
	add_filter_check(new sinsp_filter_check_utils());
	add_filter_check(new sinsp_filter_check_fdlist());
#ifndef HAS_ANALYZER
	add_filter_check(new sinsp_filter_check_k8s());
#endif // HAS_ANALYZER
	add_filter_check(new sinsp_filter_check_mesos());
	add_filter_check(new sinsp_filter_check_tracer());
	add_filter_check(new sinsp_filter_check_evtin());
}

sinsp_filter_check_list::~sinsp_filter_check_list()
{
	uint32_t j;

	for(j = 0; j < m_check_list.size(); j++)
	{
		delete m_check_list[j];
	}
}

void sinsp_filter_check_list::add_filter_check(sinsp_filter_check* filter_check)
{
	m_check_list.push_back(filter_check);
}

void sinsp_filter_check_list::get_all_fields(OUT vector<const filter_check_info*>* list)
{
	uint32_t j;

	for(j = 0; j < m_check_list.size(); j++)
	{
		list->push_back((const filter_check_info*)&(m_check_list[j]->m_info));
	}
}

sinsp_filter_check* sinsp_filter_check_list::new_filter_check_from_fldname(const string& name,
																		   sinsp* inspector,
																		   bool do_exact_check)
{
	uint32_t j;

	for(j = 0; j < m_check_list.size(); j++)
	{
		m_check_list[j]->m_inspector = inspector;

		int32_t fldnamelen = m_check_list[j]->parse_field_name(name.c_str(), false, true);

		if(fldnamelen != -1)
		{
			if(do_exact_check)
			{
				if((int32_t)name.size() != fldnamelen)
				{
					goto field_not_found;
				}
			}

			sinsp_filter_check* newchk = m_check_list[j]->allocate_new();
			newchk->set_inspector(inspector);
			return newchk;
		}
	}

field_not_found:

	//
	// If you are implementing a new filter check and this point is reached,
	// it's very likely that you've forgotten to add your filter to the list in
	// the constructor
	//
	return NULL;
}

sinsp_filter_check* sinsp_filter_check_list::new_filter_check_from_another(sinsp_filter_check *chk)
{
	sinsp_filter_check *newchk = chk->allocate_new();

	newchk->m_inspector = chk->m_inspector;
	newchk->m_field_id = chk->m_field_id;
	newchk->m_field = &chk->m_info.m_fields[chk->m_field_id];

	newchk->m_boolop = chk->m_boolop;
	newchk->m_cmpop = chk->m_cmpop;

	return newchk;
}

///////////////////////////////////////////////////////////////////////////////
// type-based comparison functions
///////////////////////////////////////////////////////////////////////////////
bool flt_compare_uint64(cmpop op, uint64_t operand1, uint64_t operand2)
{
	switch(op)
	{
	case CO_EQ:
		return (operand1 == operand2);
	case CO_NE:
		return (operand1 != operand2);
	case CO_LT:
		return (operand1 < operand2);
	case CO_LE:
		return (operand1 <= operand2);
	case CO_GT:
		return (operand1 > operand2);
	case CO_GE:
		return (operand1 >= operand2);
	case CO_CONTAINS:
		throw sinsp_exception("'contains' not supported for numeric filters");
		return false;
	case CO_ICONTAINS:
		throw sinsp_exception("'icontains' not supported for numeric filters");
		return false;
	case CO_STARTSWITH:
		throw sinsp_exception("'startswith' not supported for numeric filters");
		return false;
	case CO_GLOB:
		throw sinsp_exception("'glob' not supported for numeric filters");
		return false;
	default:
		throw sinsp_exception("'unknown' not supported for numeric filters");
		return false;
	}
}

bool flt_compare_int64(cmpop op, int64_t operand1, int64_t operand2)
{
	switch(op)
	{
	case CO_EQ:
		return (operand1 == operand2);
	case CO_NE:
		return (operand1 != operand2);
	case CO_LT:
		return (operand1 < operand2);
	case CO_LE:
		return (operand1 <= operand2);
	case CO_GT:
		return (operand1 > operand2);
	case CO_GE:
		return (operand1 >= operand2);
	case CO_CONTAINS:
		throw sinsp_exception("'contains' not supported for numeric filters");
		return false;
	case CO_ICONTAINS:
		throw sinsp_exception("'icontains' not supported for numeric filters");
		return false;
	case CO_STARTSWITH:
		throw sinsp_exception("'startswith' not supported for numeric filters");
		return false;
	case CO_GLOB:
		throw sinsp_exception("'glob' not supported for numeric filters");
		return false;
	default:
		throw sinsp_exception("'unknown' not supported for numeric filters");
		return false;
	}
}

bool flt_compare_string(cmpop op, char* operand1, char* operand2)
{
	switch(op)
	{
	case CO_EQ:
		return (strcmp(operand1, operand2) == 0);
	case CO_NE:
		return (strcmp(operand1, operand2) != 0);
	case CO_CONTAINS:
		return (strstr(operand1, operand2) != NULL);
    case CO_ICONTAINS:
#ifdef _WIN32
		return (_strnicmp(operand1, operand2, strlen(operand1)) != NULL);
#else
		return (strcasestr(operand1, operand2) != NULL);
#endif
	case CO_STARTSWITH:
		return (strncmp(operand1, operand2, strlen(operand2)) == 0);
	case CO_GLOB:
		return sinsp_utils::glob_match(operand2, operand1);
	case CO_LT:
		return (strcmp(operand1, operand2) < 0);
	case CO_LE:
		return (strcmp(operand1, operand2) <= 0);
	case CO_GT:
		return (strcmp(operand1, operand2) > 0);
	case CO_GE:
		return (strcmp(operand1, operand2) >= 0);
	default:
		ASSERT(false);
		throw sinsp_exception("invalid filter operator " + std::to_string((long long) op));
		return false;
	}
}

bool flt_compare_buffer(cmpop op, char* operand1, char* operand2, uint32_t op1_len, uint32_t op2_len)
{
	switch(op)
	{
	case CO_EQ:
		return op1_len == op2_len && (memcmp(operand1, operand2, op1_len) == 0);
	case CO_NE:
		return op1_len != op2_len || (memcmp(operand1, operand2, op1_len) != 0);
	case CO_CONTAINS:
		return (memmem(operand1, op1_len, operand2, op2_len) != NULL);
	case CO_ICONTAINS:
		throw sinsp_exception("'icontains' not supported for buffer filters");
	case CO_STARTSWITH:
		return (memcmp(operand1, operand2, op2_len) == 0);
	case CO_GLOB:
		throw sinsp_exception("'glob' not supported for buffer filters");
	case CO_LT:
		throw sinsp_exception("'<' not supported for buffer filters");
	case CO_LE:
		throw sinsp_exception("'<=' not supported for buffer filters");
	case CO_GT:
		throw sinsp_exception("'>' not supported for buffer filters");
	case CO_GE:
		throw sinsp_exception("'>=' not supported for buffer filters");
	default:
		ASSERT(false);
		throw sinsp_exception("invalid filter operator " + std::to_string((long long) op));
		return false;
	}
}

bool flt_compare_double(cmpop op, double operand1, double operand2)
{
	switch(op)
	{
	case CO_EQ:
		return (operand1 == operand2);
	case CO_NE:
		return (operand1 != operand2);
	case CO_LT:
		return (operand1 < operand2);
	case CO_LE:
		return (operand1 <= operand2);
	case CO_GT:
		return (operand1 > operand2);
	case CO_GE:
		return (operand1 >= operand2);
	case CO_CONTAINS:
		throw sinsp_exception("'contains' not supported for numeric filters");
		return false;
	case CO_ICONTAINS:
		throw sinsp_exception("'icontains' not supported for numeric filters");
		return false;
	case CO_STARTSWITH:
		throw sinsp_exception("'startswith' not supported for numeric filters");
		return false;
	case CO_GLOB:
		throw sinsp_exception("'glob' not supported for numeric filters");
		return false;
	default:
		throw sinsp_exception("'unknown' not supported for numeric filters");
		return false;
	}
}

bool flt_compare_ipv4net(cmpop op, uint64_t operand1, ipv4net* operand2)
{
	switch(op)
	{
	case CO_EQ:
	{
		return ((operand1 & operand2->m_netmask) == (operand2->m_ip & operand2->m_netmask));
	}
	case CO_NE:
		return ((operand1 & operand2->m_netmask) != (operand2->m_ip && operand2->m_netmask));
	case CO_CONTAINS:
		throw sinsp_exception("'contains' not supported for numeric filters");
		return false;
	case CO_ICONTAINS:
		throw sinsp_exception("'icontains' not supported for numeric filters");
		return false;
	case CO_STARTSWITH:
		throw sinsp_exception("'startswith' not supported for numeric filters");
		return false;
	case CO_GLOB:
		throw sinsp_exception("'glob' not supported for numeric filters");
		return false;
	default:
		throw sinsp_exception("comparison operator not supported for ipv4 networks");
	}
}

bool flt_compare(cmpop op, ppm_param_type type, void* operand1, void* operand2, uint32_t op1_len, uint32_t op2_len)
{
	//
	// sinsp_filter_check_*::compare
	// already discard NULL values
	//
	if(op == CO_EXISTS)
	{
		return true;
	}

	switch(type)
	{
	case PT_INT8:
		return flt_compare_int64(op, (int64_t)*(int8_t*)operand1, (int64_t)*(int8_t*)operand2);
	case PT_INT16:
		return flt_compare_int64(op, (int64_t)*(int16_t*)operand1, (int64_t)*(int16_t*)operand2);
	case PT_INT32:
		return flt_compare_int64(op, (int64_t)*(int32_t*)operand1, (int64_t)*(int32_t*)operand2);
	case PT_INT64:
	case PT_FD:
	case PT_PID:
	case PT_ERRNO:
		return flt_compare_int64(op, *(int64_t*)operand1, *(int64_t*)operand2);
	case PT_FLAGS8:
	case PT_UINT8:
	case PT_SIGTYPE:
		return flt_compare_uint64(op, (uint64_t)*(uint8_t*)operand1, (uint64_t)*(uint8_t*)operand2);
	case PT_FLAGS16:
	case PT_UINT16:
	case PT_PORT:
	case PT_SYSCALLID:
		return flt_compare_uint64(op, (uint64_t)*(uint16_t*)operand1, (uint64_t)*(uint16_t*)operand2);
	case PT_UINT32:
	case PT_FLAGS32:
	case PT_BOOL:
	case PT_IPV4ADDR:
		return flt_compare_uint64(op, (uint64_t)*(uint32_t*)operand1, (uint64_t)*(uint32_t*)operand2);
	case PT_IPV4NET:
		return flt_compare_ipv4net(op, (uint64_t)*(uint32_t*)operand1, (ipv4net*)operand2);
	case PT_UINT64:
	case PT_RELTIME:
	case PT_ABSTIME:
		return flt_compare_uint64(op, *(uint64_t*)operand1, *(uint64_t*)operand2);
	case PT_CHARBUF:
		return flt_compare_string(op, (char*)operand1, (char*)operand2);
	case PT_BYTEBUF:
		return flt_compare_buffer(op, (char*)operand1, (char*)operand2, op1_len, op2_len);
	case PT_DOUBLE:
		return flt_compare_double(op, *(double*)operand1, *(double*)operand2);
	case PT_SOCKADDR:
	case PT_SOCKTUPLE:
	case PT_FDLIST:
	case PT_FSPATH:
	case PT_SIGSET:
	default:
		ASSERT(false);
		return false;
	}
}

bool flt_compare_avg(cmpop op,
					 ppm_param_type type,
					 void* operand1,
					 void* operand2,
					 uint32_t op1_len,
					 uint32_t op2_len,
					 uint32_t cnt1,
					 uint32_t cnt2)
{
	int64_t i641, i642;
	uint64_t u641, u642;
	double d1, d2;

	//
	// If count = 0 we assume that the value is zero too (there are assertions to
	// check that, and we just divide by 1
	//
	if(cnt1 == 0)
	{
		cnt1 = 1;
	}

	if(cnt2 == 0)
	{
		cnt2 = 1;
	}

	switch(type)
	{
	case PT_INT8:
		i641 = ((int64_t)*(int8_t*)operand1) / cnt1;
		i642 = ((int64_t)*(int8_t*)operand2) / cnt2;
		ASSERT(cnt1 != 0 || i641 == 0);
		ASSERT(cnt2 != 0 || i642 == 0);
		return flt_compare_int64(op, i641, i642);
	case PT_INT16:
		i641 = ((int64_t)*(int16_t*)operand1) / cnt1;
		i642 = ((int64_t)*(int16_t*)operand2) / cnt2;
		ASSERT(cnt1 != 0 || i641 == 0);
		ASSERT(cnt2 != 0 || i642 == 0);
		return flt_compare_int64(op, i641, i642);
	case PT_INT32:
		i641 = ((int64_t)*(int32_t*)operand1) / cnt1;
		i642 = ((int64_t)*(int32_t*)operand2) / cnt2;
		ASSERT(cnt1 != 0 || i641 == 0);
		ASSERT(cnt2 != 0 || i642 == 0);
		return flt_compare_int64(op, i641, i642);
	case PT_INT64:
	case PT_FD:
	case PT_PID:
	case PT_ERRNO:
		i641 = ((int64_t)*(int64_t*)operand1) / cnt1;
		i642 = ((int64_t)*(int64_t*)operand2) / cnt2;
		ASSERT(cnt1 != 0 || i641 == 0);
		ASSERT(cnt2 != 0 || i642 == 0);
		return flt_compare_int64(op, i641, i642);
	case PT_FLAGS8:
	case PT_UINT8:
	case PT_SIGTYPE:
		u641 = ((uint64_t)*(uint8_t*)operand1) / cnt1;
		u642 = ((uint64_t)*(uint8_t*)operand2) / cnt2;
		ASSERT(cnt1 != 0 || u641 == 0);
		ASSERT(cnt2 != 0 || u642 == 0);
		return flt_compare_uint64(op, u641, u642);
	case PT_FLAGS16:
	case PT_UINT16:
	case PT_PORT:
	case PT_SYSCALLID:
		u641 = ((uint64_t)*(uint16_t*)operand1) / cnt1;
		u642 = ((uint64_t)*(uint16_t*)operand2) / cnt2;
		ASSERT(cnt1 != 0 || u641 == 0);
		ASSERT(cnt2 != 0 || u642 == 0);
		return flt_compare_uint64(op, u641, u642);
	case PT_UINT32:
	case PT_FLAGS32:
	case PT_BOOL:
	case PT_IPV4ADDR:
		u641 = ((uint64_t)*(uint32_t*)operand1) / cnt1;
		u642 = ((uint64_t)*(uint32_t*)operand2) / cnt2;
		ASSERT(cnt1 != 0 || u641 == 0);
		ASSERT(cnt2 != 0 || u642 == 0);
		return flt_compare_uint64(op, u641, u642);
	case PT_UINT64:
	case PT_RELTIME:
	case PT_ABSTIME:
		u641 = (*(uint64_t*)operand1) / cnt1;
		u642 = (*(uint64_t*)operand2) / cnt2;
		ASSERT(cnt1 != 0 || u641 == 0);
		ASSERT(cnt2 != 0 || u642 == 0);
		return flt_compare_uint64(op, u641, u642);
	case PT_DOUBLE:
		d1 = (*(double*)operand1) / cnt1;
		d2 = (*(double*)operand2) / cnt2;
		ASSERT(cnt1 != 0 || d1 == 0);
		ASSERT(cnt2 != 0 || d2 == 0);
		return flt_compare_double(op, d1, d2);
	default:
		ASSERT(false);
		return false;
	}
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_filter_check::sinsp_filter_check()
{
	m_boolop = BO_NONE;
	m_cmpop = CO_NONE;
	m_inspector = NULL;
	m_field = NULL;
	m_info.m_fields = NULL;
	m_info.m_nfields = -1;
	m_val_storage_len = 0;
	m_aggregation = A_NONE;
	m_merge_aggregation = A_NONE;
	m_val_storages = vector<vector<uint8_t>> (1, vector<uint8_t>(256));
	m_val_storages_min_size = (numeric_limits<uint32_t>::max)();
	m_val_storages_max_size = (numeric_limits<uint32_t>::min)();
}

void sinsp_filter_check::set_inspector(sinsp* inspector)
{
	m_inspector = inspector;
}

Json::Value sinsp_filter_check::rawval_to_json(uint8_t* rawval, const filtercheck_field_info* finfo, uint32_t len)
{
	ASSERT(rawval != NULL);
	ASSERT(finfo != NULL);

	switch(finfo->m_type)
	{
		case PT_INT8:
			if(finfo->m_print_format == PF_DEC ||
			   finfo->m_print_format == PF_ID)
			{
				return *(int8_t *)rawval;
			}
			else if(finfo->m_print_format == PF_HEX)
			{
				return rawval_to_string(rawval, finfo, len);
			}
			else
			{
				ASSERT(false);
				return Json::nullValue;
			}

		case PT_INT16:
			if(finfo->m_print_format == PF_DEC ||
			   finfo->m_print_format == PF_ID)
			{
				return *(int16_t *)rawval;
			}
			else if(finfo->m_print_format == PF_HEX)
			{
				return rawval_to_string(rawval, finfo, len);
			}
			else
			{
				ASSERT(false);
				return Json::nullValue;
			}

		case PT_INT32:
			if(finfo->m_print_format == PF_DEC ||
			   finfo->m_print_format == PF_ID)
			{
				return *(int32_t *)rawval;
			}
			else if(finfo->m_print_format == PF_HEX)
			{
				return rawval_to_string(rawval, finfo, len);
			}
			else
			{
				ASSERT(false);
				return Json::nullValue;
			}

		case PT_INT64:
		case PT_PID:
			if(finfo->m_print_format == PF_DEC ||
			   finfo->m_print_format == PF_ID)
			{
		 		return (Json::Value::Int64)*(int64_t *)rawval;
			}
			else
			{
				return rawval_to_string(rawval, finfo, len);
			}

		case PT_L4PROTO: // This can be resolved in the future
		case PT_UINT8:
			if(finfo->m_print_format == PF_DEC ||
			   finfo->m_print_format == PF_ID)
			{
				return *(uint8_t *)rawval;
			}
			else if(finfo->m_print_format == PF_HEX)
			{
				return rawval_to_string(rawval, finfo, len);
			}
			else
			{
				ASSERT(false);
				return Json::nullValue;
			}

		case PT_PORT: // This can be resolved in the future
		case PT_UINT16:
			if(finfo->m_print_format == PF_DEC ||
			   finfo->m_print_format == PF_ID)
			{
				return *(uint16_t *)rawval;
			}
			else if(finfo->m_print_format == PF_HEX)
			{
				return rawval_to_string(rawval, finfo, len);
			}
			else
			{
				ASSERT(false);
				return Json::nullValue;
			}

		case PT_UINT32:
			if(finfo->m_print_format == PF_DEC ||
			   finfo->m_print_format == PF_ID)
			{
				return *(uint32_t *)rawval;
			}
			else if(finfo->m_print_format == PF_HEX)
			{
				return rawval_to_string(rawval, finfo, len);
			}
			else
			{
				ASSERT(false);
				return Json::nullValue;
			}

		case PT_UINT64:
		case PT_RELTIME:
		case PT_ABSTIME:
			if(finfo->m_print_format == PF_DEC ||
			   finfo->m_print_format == PF_ID)
			{
				return (Json::Value::UInt64)*(uint64_t *)rawval;
			}
			else if(
				finfo->m_print_format == PF_10_PADDED_DEC ||
				finfo->m_print_format == PF_HEX)
			{
				return rawval_to_string(rawval, finfo, len);
			}
			else
			{
				ASSERT(false);
				return Json::nullValue;
			}

		case PT_SOCKADDR:
		case PT_SOCKFAMILY:
			ASSERT(false);
			return Json::nullValue;

		case PT_BOOL:
			return Json::Value((bool)(*(uint32_t*)rawval != 0));

		case PT_CHARBUF:
		case PT_FSPATH:
		case PT_BYTEBUF:
		case PT_IPV4ADDR:
			return rawval_to_string(rawval, finfo, len);

		default:
			ASSERT(false);
			throw sinsp_exception("wrong event type " + to_string((long long) finfo->m_type));
	}
}

char* sinsp_filter_check::rawval_to_string(uint8_t* rawval, const filtercheck_field_info* finfo, uint32_t len)
{
	char* prfmt;

	ASSERT(rawval != NULL);
	ASSERT(finfo != NULL);

	switch(finfo->m_type)
	{
		case PT_INT8:
			if(finfo->m_print_format == PF_DEC ||
			   finfo->m_print_format == PF_ID)
			{
				prfmt = (char*)"%" PRId8;
			}
			else if(finfo->m_print_format == PF_HEX)
			{
				prfmt = (char*)"%" PRIX8;
			}
			else
			{
				ASSERT(false);
				return NULL;
			}

			snprintf(m_getpropertystr_storage,
					 sizeof(m_getpropertystr_storage),
					 prfmt, *(int8_t *)rawval);
			return m_getpropertystr_storage;
		case PT_INT16:
			if(finfo->m_print_format == PF_DEC ||
			   finfo->m_print_format == PF_ID)
			{
				prfmt = (char*)"%" PRId16;
			}
			else if(finfo->m_print_format == PF_HEX)
			{
				prfmt = (char*)"%" PRIX16;
			}
			else
			{
				ASSERT(false);
				return NULL;
			}

			snprintf(m_getpropertystr_storage,
					 sizeof(m_getpropertystr_storage),
					 prfmt, *(int16_t *)rawval);
			return m_getpropertystr_storage;
		case PT_INT32:
			if(finfo->m_print_format == PF_DEC ||
			   finfo->m_print_format == PF_ID)
			{
				prfmt = (char*)"%" PRId32;
			}
			else if(finfo->m_print_format == PF_HEX)
			{
				prfmt = (char*)"%" PRIX32;
			}
			else
			{
				ASSERT(false);
				return NULL;
			}

			snprintf(m_getpropertystr_storage,
					 sizeof(m_getpropertystr_storage),
					 prfmt, *(int32_t *)rawval);
			return m_getpropertystr_storage;
		case PT_INT64:
		case PT_PID:
		case PT_ERRNO:
			if(finfo->m_print_format == PF_DEC ||
			   finfo->m_print_format == PF_ID)
			{
				prfmt = (char*)"%" PRId64;
			}
			else if(finfo->m_print_format == PF_10_PADDED_DEC)
			{
				prfmt = (char*)"%09" PRId64;
			}
			else if(finfo->m_print_format == PF_HEX)
			{
				prfmt = (char*)"%" PRIX64;
			}
			else
			{
				prfmt = (char*)"%" PRId64;
			}

			snprintf(m_getpropertystr_storage,
					 sizeof(m_getpropertystr_storage),
					 prfmt, *(int64_t *)rawval);
			return m_getpropertystr_storage;
		case PT_L4PROTO: // This can be resolved in the future
		case PT_UINT8:
			if(finfo->m_print_format == PF_DEC ||
			   finfo->m_print_format == PF_ID)
			{
				prfmt = (char*)"%" PRIu8;
			}
			else if(finfo->m_print_format == PF_HEX)
			{
				prfmt = (char*)"%" PRIu8;
			}
			else
			{
				ASSERT(false);
				return NULL;
			}

			snprintf(m_getpropertystr_storage,
					 sizeof(m_getpropertystr_storage),
					 prfmt, *(uint8_t *)rawval);
			return m_getpropertystr_storage;
		case PT_PORT: // This can be resolved in the future
		case PT_UINT16:
			if(finfo->m_print_format == PF_DEC ||
			   finfo->m_print_format == PF_ID)
			{
				prfmt = (char*)"%" PRIu16;
			}
			else if(finfo->m_print_format == PF_HEX)
			{
				prfmt = (char*)"%" PRIu16;
			}
			else
			{
				ASSERT(false);
				return NULL;
			}

			snprintf(m_getpropertystr_storage,
					 sizeof(m_getpropertystr_storage),
					 prfmt, *(uint16_t *)rawval);
			return m_getpropertystr_storage;
		case PT_UINT32:
			if(finfo->m_print_format == PF_DEC ||
			   finfo->m_print_format == PF_ID)
			{
				prfmt = (char*)"%" PRIu32;
			}
			else if(finfo->m_print_format == PF_HEX)
			{
				prfmt = (char*)"%" PRIu32;
			}
			else
			{
				ASSERT(false);
				return NULL;
			}

			snprintf(m_getpropertystr_storage,
					 sizeof(m_getpropertystr_storage),
					 prfmt, *(uint32_t *)rawval);
			return m_getpropertystr_storage;
		case PT_UINT64:
		case PT_RELTIME:
		case PT_ABSTIME:
			if(finfo->m_print_format == PF_DEC ||
			   finfo->m_print_format == PF_ID)
			{
				prfmt = (char*)"%" PRIu64;
			}
			else if(finfo->m_print_format == PF_10_PADDED_DEC)
			{
				prfmt = (char*)"%09" PRIu64;
			}
			else if(finfo->m_print_format == PF_HEX)
			{
				prfmt = (char*)"%" PRIX64;
			}
			else
			{
				ASSERT(false);
				return NULL;
			}

			snprintf(m_getpropertystr_storage,
					 sizeof(m_getpropertystr_storage),
					 prfmt, *(uint64_t *)rawval);
			return m_getpropertystr_storage;
		case PT_CHARBUF:
		case PT_FSPATH:
			return (char*)rawval;
		case PT_BYTEBUF:
			if(rawval[len] == 0)
			{
				return (char*)rawval;
			}
			else
			{
				ASSERT(len < 1024 * 1024);

				if(len >= filter_value().size())
				{
					filter_value().resize(len + 1);
				}

				memcpy(filter_value_p(), rawval, len);
				filter_value_p()[len] = 0;
				return (char*)filter_value_p();
			}
		case PT_SOCKADDR:
			ASSERT(false);
			return NULL;
		case PT_SOCKFAMILY:
			ASSERT(false);
			return NULL;
		case PT_BOOL:
			if(*(uint32_t*)rawval != 0)
			{
				return (char*)"true";
			}
			else
			{
				return (char*)"false";
			}
		case PT_IPV4ADDR:
			snprintf(m_getpropertystr_storage,
						sizeof(m_getpropertystr_storage),
						"%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8,
						rawval[0],
						rawval[1],
						rawval[2],
						rawval[3]);
			return m_getpropertystr_storage;
		case PT_DOUBLE:
			snprintf(m_getpropertystr_storage,
					 sizeof(m_getpropertystr_storage),
					 "%.1lf", *(double*)rawval);
			return m_getpropertystr_storage;
		default:
			ASSERT(false);
			throw sinsp_exception("wrong event type " + to_string((long long) finfo->m_type));
	}
}

char* sinsp_filter_check::tostring(sinsp_evt* evt)
{
	uint32_t len;
	uint8_t* rawval = extract(evt, &len);

	if(rawval == NULL)
	{
		return NULL;
	}

	return rawval_to_string(rawval, m_field, len);
}

Json::Value sinsp_filter_check::tojson(sinsp_evt* evt)
{
	uint32_t len;
	Json::Value jsonval = extract_as_js(evt, &len);

	if(jsonval == Json::nullValue)
	{
		uint8_t* rawval = extract(evt, &len);
		if(rawval == NULL)
		{
			return Json::nullValue;
		}
		return rawval_to_json(rawval, m_field, len);
	}

	return jsonval;
}

int32_t sinsp_filter_check::parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering)
{
	int32_t j;
	int32_t max_fldlen = -1;
	uint32_t max_flags = 0;

	ASSERT(m_info.m_fields != NULL);
	ASSERT(m_info.m_nfields != -1);

	string val(str);

	m_field_id = 0xffffffff;

	for(j = 0; j < m_info.m_nfields; j++)
	{
		string fldname = m_info.m_fields[j].m_name;
		int32_t fldlen = (uint32_t)fldname.length();

		if(val.compare(0, fldlen, fldname) == 0)
		{
			if(fldlen > max_fldlen)
			{
				m_field_id = j;
				m_field = &m_info.m_fields[j];
				max_fldlen = fldlen;
				max_flags = (m_info.m_fields[j]).m_flags;
			}
		}
	}

	if(!needed_for_filtering)
	{
		if(max_flags & EPF_FILTER_ONLY)
		{
			throw sinsp_exception(string(str) + " is filter only and cannot be used as a display field");
		}
	}

	return max_fldlen;
}

void sinsp_filter_check::set_check_id(int32_t id)
{
	m_check_id = id;
}

int32_t sinsp_filter_check::get_check_id()
{
	return m_check_id;
}


void sinsp_filter_check::add_filter_value(const char* str, uint32_t len, uint32_t i)
{

	if (i >= m_val_storages.size())
	{
		m_val_storages.push_back(vector<uint8_t>(256));
	}

	parse_filter_value(str, len, filter_value_p(i), filter_value(i).size());

	// XXX/mstemm this doesn't work if someone called
	// add_filter_value more than once for a given index.
	filter_value_t item(filter_value_p(i), len);
	m_val_storages_members.insert(item);

	if(len < m_val_storages_min_size)
	{
		m_val_storages_min_size = len;
	}

	if(len > m_val_storages_max_size)
	{
		m_val_storages_max_size = len;
	}

	// If the operator is CO_PMATCH, also add the value to the paths set.
	if (m_cmpop == CO_PMATCH)
	{
		m_val_storages_paths.add_search_path(item);
	}
}

void sinsp_filter_check::parse_filter_value(const char* str, uint32_t len, uint8_t *storage, uint32_t storage_len)
{
	// byte buffer, no parsing needed
	if (m_field->m_type == PT_BYTEBUF)
	{
		if(len >= storage_len)
		{
			throw sinsp_exception("filter parameter too long:" + string(str));
		}
		memcpy(storage, str, len);
		m_val_storage_len = len;
		return;
	}
	else
	{
		sinsp_filter_value_parser::string_to_rawval(str, len, storage, storage_len, m_field->m_type);
	}
	validate_filter_value(str, len);
}

const filtercheck_field_info* sinsp_filter_check::get_field_info()
{
	return &m_info.m_fields[m_field_id];
}

bool sinsp_filter_check::flt_compare(cmpop op, ppm_param_type type, void* operand1, uint32_t op1_len, uint32_t op2_len)
{
	if (op == CO_IN || op == CO_PMATCH)
	{
		// For raw strings, the length may not be set. So we do a strlen to find it.
		if(type == PT_CHARBUF && op1_len == 0)
		{
			op1_len = strlen((char *) operand1);
		}

		filter_value_t item((uint8_t *) operand1, op1_len);

		if (op == CO_IN)
		{
			if(op1_len >= m_val_storages_min_size &&
			   op1_len <= m_val_storages_max_size &&
			   m_val_storages_members.find(item) != m_val_storages_members.end())
			{
				return true;
			}
		}
		else
		{
			if (m_val_storages_paths.match(item))
			{
				return true;
			}
		}

		return false;
	}
	else
	{
		return (::flt_compare(op,
				      type,
				      operand1,
				      filter_value_p(),
				      op1_len,
				      op2_len)
			);
	}
}

bool sinsp_filter_check::compare(sinsp_evt *evt)
{
	uint32_t evt_val_len=0;
	bool sanitize_strings = false;
	uint8_t* extracted_val = extract(evt, &evt_val_len, sanitize_strings);

	if(extracted_val == NULL)
	{
		return false;
	}

	return flt_compare(m_cmpop,
			   m_info.m_fields[m_field_id].m_type,
			   extracted_val,
			   evt_val_len,
			   m_val_storage_len);
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_expression implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_filter_expression::sinsp_filter_expression()
{
	m_parent = NULL;
}

sinsp_filter_expression::~sinsp_filter_expression()
{
	uint32_t j;

	for(j = 0; j < m_checks.size(); j++)
	{
		delete m_checks[j];
	}
}

// Only filter checks get IDs
int32_t sinsp_filter_expression::get_check_id()
{
	return 0;
}

sinsp_filter_check* sinsp_filter_expression::allocate_new()
{
	ASSERT(false);
	return NULL;
}

void sinsp_filter_expression::add_check(sinsp_filter_check* chk)
{
	m_checks.push_back(chk);
}

void sinsp_filter_expression::parse(string expr)
{
}

bool sinsp_filter_expression::compare(sinsp_evt *evt)
{
	uint32_t j;
	uint32_t size = (uint32_t)m_checks.size();
	bool res = true;
	sinsp_filter_check* chk = NULL;

	for(j = 0; j < size; j++)
	{
		chk = m_checks[j];
		ASSERT(chk != NULL);

		if(j == 0)
		{
			switch(chk->m_boolop)
			{
			case BO_NONE:
				res = chk->compare(evt);
				if (res) {
					evt->set_check_id(chk->get_check_id());
				}
				break;
			case BO_NOT:
				res = !chk->compare(evt);
				break;
			default:
				ASSERT(false);
				break;
			}
		}
		else
		{
			switch(chk->m_boolop)
			{
			case BO_OR:
				if(res)
				{
					goto done;
				}
				res = chk->compare(evt);
				if (res) {
					evt->set_check_id(chk->get_check_id());
				}
				break;
			case BO_AND:
				if(!res)
				{
					goto done;
				}
				res = chk->compare(evt);
				if (res) {
					evt->set_check_id(chk->get_check_id());
				}
				break;
			case BO_ORNOT:
				if(res)
				{
					goto done;
				}
				res = !chk->compare(evt);
				if (res) {
					evt->set_check_id(chk->get_check_id());
				}
				break;
			case BO_ANDNOT:
				if(!res)
				{
					goto done;
				}
				res = !chk->compare(evt);
				if (res) {
					evt->set_check_id(chk->get_check_id());
				}
				break;
			default:
				ASSERT(false);
				break;
			}
		}
	}
 done:

	return res;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_filter::sinsp_filter(sinsp* inspector)
{
	m_inspector = inspector;
	m_filter = new sinsp_filter_expression();
	m_curexpr = m_filter;

}

sinsp_filter::~sinsp_filter()
{
	if(m_filter)
	{
		delete m_filter;
	}
}

void sinsp_filter::push_expression(boolop op)
{
	sinsp_filter_expression* newexpr = new sinsp_filter_expression();
	newexpr->m_boolop = op;
	newexpr->m_parent = m_curexpr;

	add_check((sinsp_filter_check*)newexpr);
	m_curexpr = newexpr;
}

void sinsp_filter::pop_expression()
{
	ASSERT(m_curexpr->m_parent != NULL);

	m_curexpr = m_curexpr->m_parent;
}

bool sinsp_filter::run(sinsp_evt *evt)
{
	//	printf("m_filter: %p", (void*) m_filter);
	//	ASSERT(m_filter != NULL);
	return m_filter->compare(evt);
}

void sinsp_filter::add_check(sinsp_filter_check* chk)
{
	m_curexpr->add_check(chk);
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_compiler implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_filter_compiler::sinsp_filter_compiler(sinsp* inspector, const string& fltstr, bool ttable_only)
{
	m_inspector = inspector;
	m_ttable_only = ttable_only;
	m_scanpos = -1;
	m_scansize = 0;
	m_state = ST_NEED_EXPRESSION;
	m_filter = new sinsp_filter(m_inspector);
	m_last_boolop = BO_NONE;
	m_nest_level = 0;
	m_fltstr = fltstr;
}

sinsp_filter_compiler::~sinsp_filter_compiler()
{
}

bool sinsp_filter_compiler::isblank(char c)
{
	if(c == ' ' || c == '\t' || c == '\n' || c == '\r')
	{
		return true;
	}
	else
	{
		return false;
	}
}

bool sinsp_filter_compiler::is_special_char(char c)
{
	if(c == '(' || c == ')' || c == '!' || c == '=' || c == '<' || c == '>')
	{
		return true;
	}

	return false;
}

bool sinsp_filter_compiler::is_bracket(char c)
{
	if(c == '(' || c == ')')
	{
		return true;
	}

	return false;
}

char sinsp_filter_compiler::next()
{
	while(true)
	{
		m_scanpos++;

		if(m_scanpos >= m_scansize)
		{
			return 0;
		}

		if(!isblank(m_fltstr[m_scanpos]))
		{
			return m_fltstr[m_scanpos];
		}
	}
}

vector<char> sinsp_filter_compiler::next_operand(bool expecting_first_operand, bool in_or_pmatch_clause)
{
	vector<char> res;
	bool is_quoted = false;
	int32_t start;
	int32_t nums[2];
	uint32_t num_pos;
	enum ppm_escape_state
	{
		PES_NORMAL,
		PES_SLASH,
		PES_NUMBER,
		PES_ERROR,
	} escape_state;

	//
	// Skip spaces
	//
	if(isblank(m_fltstr[m_scanpos]))
	{
		next();
	}

	//
	// If there are quotes, don't stop on blank
	//
	if(m_scanpos < m_scansize &&
		(m_fltstr[m_scanpos] == '"' || m_fltstr[m_scanpos] == '\''))
	{
		is_quoted = true;
		m_scanpos++;
	}

	//
	// Mark the beginning of the word
	//
	start = m_scanpos;
	escape_state = PES_NORMAL;
	num_pos = 0;

	while(m_scanpos < m_scansize && escape_state != PES_ERROR)
	{
		char curchar = m_fltstr[m_scanpos];
		bool is_end_of_word;

		if(expecting_first_operand)
		{
			is_end_of_word = (isblank(curchar) || is_special_char(curchar));
		}
		else
		{
			is_end_of_word = (!is_quoted && (isblank(curchar) || is_bracket(curchar) || (in_or_pmatch_clause && curchar == ','))) ||
				(is_quoted && escape_state != PES_SLASH && (curchar == '"' || curchar == '\''));
		}

		if(is_end_of_word)
		{
			if(escape_state != PES_NORMAL)
			{
				escape_state = PES_ERROR;
				break;
			}

			//
			// End of word
			//
			ASSERT(m_scanpos >= start);

			if(curchar == '(' || curchar == ')' || (in_or_pmatch_clause && curchar == ','))
			{
				m_scanpos--;
			}

			res.push_back('\0');
			return res;
		}

		switch(escape_state)
		{
		case PES_NORMAL:
			if(curchar == '\\' && !expecting_first_operand)
			{
				escape_state = PES_SLASH;
			}
			else
			{
				res.push_back(curchar);
			}
			break;
		case PES_SLASH:
			switch(curchar)
			{
			case '\\':
			case '"':
				escape_state = PES_NORMAL;
				res.push_back(curchar);
				break;
			case 'x':
				escape_state = PES_NUMBER;
				break;
			default:
				escape_state = PES_NORMAL;
				res.push_back('\\');
				res.push_back(curchar);
				break;
			}
			break;
		case PES_NUMBER:
			if(isdigit((int)curchar))
			{
				nums[num_pos++] = curchar - '0';
			}
			else if((curchar >= 'a' && curchar <= 'f') || (curchar >= 'A' && curchar <= 'F'))
			{
				nums[num_pos++] = tolower((int)curchar) - 'a' + 10;
			}
			else
			{
				escape_state = PES_ERROR;
			}

			if(num_pos == 2 && escape_state != PES_ERROR)
			{
				res.push_back((char)(nums[0] * 16 + nums[1]));

				num_pos = 0;
				escape_state = PES_NORMAL;
			}
			break;
		default:
			ASSERT(false);
			escape_state = PES_ERROR;
			break;
		}

		m_scanpos++;
	}

	if(escape_state == PES_ERROR)
	{
		throw sinsp_exception("filter error: unrecognized escape sequence at " + m_fltstr.substr(start, m_scanpos));
	}
	else if(is_quoted)
	{
		throw sinsp_exception("filter error: unclosed quotes");
	}

	//
	// End of filter
	//
	res.push_back('\0');
	return res;
}

bool sinsp_filter_compiler::compare_no_consume(const string& str)
{
	//
	// If the rest of the filter cannot contain the operand we may return
	// The filter may finish with the operand itself though (e.g. "proc.name exists")
	//
	if(m_scanpos + (int32_t)str.size() > m_scansize)
	{
		return false;
	}

	string tstr = m_fltstr.substr(m_scanpos, str.size());

	if(tstr == str)
	{
		return true;
	}
	else
	{
		return false;
	}
}

cmpop sinsp_filter_compiler::next_comparison_operator()
{
	int32_t start;

	//
	// Skip spaces
	//
	if(isblank(m_fltstr[m_scanpos]))
	{
		next();
	}

	//
	// Mark the beginning of the word
	//
	start = m_scanpos;

	if(compare_no_consume("="))
	{
		m_scanpos += 1;
		return CO_EQ;
	}
	else if(compare_no_consume("!="))
	{
		m_scanpos += 2;
		return CO_NE;
	}
	else if(compare_no_consume("<="))
	{
		m_scanpos += 2;
		return CO_LE;
	}
	else if(compare_no_consume("<"))
	{
		m_scanpos += 1;
		return CO_LT;
	}
	else if(compare_no_consume(">="))
	{
		m_scanpos += 2;
		return CO_GE;
	}
	else if(compare_no_consume(">"))
	{
		m_scanpos += 1;
		return CO_GT;
	}
	else if(compare_no_consume("contains"))
	{
		m_scanpos += 8;
		return CO_CONTAINS;
	}
	else if(compare_no_consume("icontains"))
	{
		m_scanpos += 9;
		return CO_ICONTAINS;
	}
	else if(compare_no_consume("startswith"))
	{
		m_scanpos += 10;
		return CO_STARTSWITH;
	}
	else if(compare_no_consume("glob"))
	{
		m_scanpos += 4;
		return CO_GLOB;
	}
	else if(compare_no_consume("in"))
	{
		m_scanpos += 2;
		return CO_IN;
	}
	else if(compare_no_consume("pmatch"))
	{
		m_scanpos += 6;
		return CO_PMATCH;
	}
	else if(compare_no_consume("exists"))
	{
		m_scanpos += 6;
		return CO_EXISTS;
	}
	else
	{
		throw sinsp_exception("filter error: unrecognized comparison operator after " + m_fltstr.substr(0, start));
	}
}

void sinsp_filter_compiler::parse_check()
{
	uint32_t startpos = m_scanpos;
	vector<char> operand1 = next_operand(true, false);
	string str_operand1 = string((char *)&operand1[0]);
	sinsp_filter_check* chk = g_filterlist.new_filter_check_from_fldname(str_operand1, m_inspector, true);
	boolop op = m_last_boolop;

	if(chk == NULL)
	{
		throw sinsp_exception("filter error: unrecognized field " +
			str_operand1 + " at pos " + to_string((long long) startpos));
	}

	if(m_ttable_only)
	{
		if(!(chk->get_fields()->m_flags & filter_check_info::FL_WORKS_ON_THREAD_TABLE))
		{
			throw sinsp_exception("the given filter is not supported for thread table filtering");
		}
	}

	cmpop co = next_comparison_operator();

	chk->m_boolop = op;
	chk->m_cmpop = co;

	chk->parse_field_name((char *)&operand1[0], true, true);

	if(co == CO_IN || co == CO_PMATCH)
	{
		//
		// Skip spaces
		//
		if(isblank(m_fltstr[m_scanpos]))
		{
			next();
		}

		if(m_fltstr[m_scanpos] != '(')
		{
			throw sinsp_exception("expected '(' after 'in/pmatch' operand");
		}

		//
		// Skip '('
		//
		m_scanpos++;

		if(chk->get_field_info()->m_type == PT_CHARBUF)
		{
			//
			// For character buffers, we can check all
			// values at once by putting them in a set and
			// checking for set membership.
			//

			//
			// Create the 'or' sequence
			//
			uint32_t num_values = 0;
			while(true)
			{
				// 'in' clause aware
				vector<char> operand2 = next_operand(false, true);

				chk->add_filter_value((char *)&operand2[0], (uint32_t)operand2.size() - 1, num_values);
				num_values++;
				next();

				if(m_fltstr[m_scanpos] == ')')
				{
					break;
				}
				else if(m_fltstr[m_scanpos] == ',')
				{
					m_scanpos++;
				}
				else
				{
					throw sinsp_exception("expected either ')' or ',' after a value inside the 'in/pmatch' clause");
				}
			}
			m_filter->add_check(chk);
		}
		else if (co == CO_PMATCH)
		{
			// the pmatch operator can only work on charbufs
			throw sinsp_exception("pmatch requires all charbuf arguments");
		}
		else
		{
			//
			// In this case we need to create '(field=value1 or field=value2 ...)'
			//

			//
			// Separate the 'or's from the
			// rest of the conditions
			//
			m_filter->push_expression(op);
			m_last_boolop = BO_NONE;
			m_nest_level++;

			//
			// The first boolean operand will be BO_NONE
			// Then we will start putting BO_ORs
			//
			op = BO_NONE;

			//
			// Create the 'or' sequence
			//
			uint32_t num_values = 0;
			while(true)
			{
				// 'in' clause aware
				vector<char> operand2 = next_operand(false, true);

				//
				// Append every sinsp_filter_check creating the 'or' sequence
				//
				sinsp_filter_check* newchk = g_filterlist.new_filter_check_from_another(chk);
				newchk->m_boolop = op;
				newchk->m_cmpop = CO_EQ;
				newchk->add_filter_value((char *)&operand2[0], (uint32_t)operand2.size() - 1, num_values);
				num_values++;

				m_filter->add_check(newchk);

				next();

				if(m_fltstr[m_scanpos] == ')')
				{
					break;
				}
				else if(m_fltstr[m_scanpos] == ',')
				{
					m_scanpos++;
				}
				else
				{
					throw sinsp_exception("expected either ')' or ',' after a value inside the 'in' clause");
				}

				//
				// From now on we 'or' every newchk
				//
				op = BO_OR;
			}

			//
			// Come back to the rest of the filter
			//
			m_filter->pop_expression();
			m_nest_level--;
		}
	}
	else
	{
		//
		// In this case we want next() to return the very next character
		// At this moment m_scanpos is already at it
		// e.g. "(field exists) and ..."
		//
		if(co == CO_EXISTS)
		{
			m_scanpos--;
		}
		//
		// Otherwise we need a value for the operand
		//
		else
		{
			vector<char> operand2 = next_operand(false, false);
			chk->add_filter_value((char *)&operand2[0], (uint32_t)operand2.size() - 1);
		}

		m_filter->add_check(chk);
	}
}

sinsp_filter* sinsp_filter_compiler::compile()
{
	try
	{
		return compile_();
	}
	catch(sinsp_exception& e)
	{
		delete m_filter;
		throw e;
	}
	catch(...)
	{
		delete m_filter;
		throw sinsp_exception("error parsing the filter string");
	}
}

sinsp_filter* sinsp_filter_compiler::compile_()
{
	m_scansize = (uint32_t)m_fltstr.size();

	while(true)
	{
		char a = next();

		switch(a)
		{
		case 0:
			//
			// Finished parsing the filter string
			//
			if(m_nest_level != 0)
			{
				throw sinsp_exception("filter error: unexpected end of filter");
			}

			if(m_state != ST_EXPRESSION_DONE)
			{
				throw sinsp_exception("filter error: unexpected end of filter at position " + to_string((long long) m_scanpos));
			}

			//
			// Good filter
			//
			return m_filter;

			break;
		case '(':
			if(m_state != ST_NEED_EXPRESSION)
			{
				throw sinsp_exception("unexpected '(' after " + m_fltstr.substr(0, m_scanpos));
			}

			m_filter->push_expression(m_last_boolop);
			m_last_boolop = BO_NONE;
			m_nest_level++;

			break;
		case ')':
			m_filter->pop_expression();
			m_nest_level--;
			break;
		case 'o':
			if(m_scanpos != 0 && m_state != ST_NEED_EXPRESSION)
			{
				if(next() == 'r')
				{
					m_last_boolop = BO_OR;
				}
				else
				{
					throw sinsp_exception("syntax error in filter at position " + to_string((long long)m_scanpos));
				}

				if(m_state != ST_EXPRESSION_DONE)
				{
					throw sinsp_exception("unexpected 'or' after " + m_fltstr.substr(0, m_scanpos));
				}

				m_state = ST_NEED_EXPRESSION;
			}
			else
			{
				parse_check();
				m_state = ST_EXPRESSION_DONE;
			}

			break;
		case 'a':
			if(m_scanpos != 0 && m_state != ST_NEED_EXPRESSION)
			{

				if(next() == 'n' && next() == 'd')
				{
					m_last_boolop = BO_AND;
				}
				else
				{
					throw sinsp_exception("syntax error in filter at position " + to_string((long long)m_scanpos));
				}

				if(m_state != ST_EXPRESSION_DONE)
				{
					throw sinsp_exception("unexpected 'and' after " + m_fltstr.substr(0, m_scanpos));
				}

				m_state = ST_NEED_EXPRESSION;
			}
			else
			{
				parse_check();
				m_state = ST_EXPRESSION_DONE;
			}

			break;
		case 'n':
			if(next() == 'o' && next() == 't')
			{
				m_last_boolop = (boolop)((uint32_t)m_last_boolop | BO_NOT);
			}
			else
			{
				throw sinsp_exception("syntax error in filter at position " + to_string((long long) m_scanpos));
			}

			if(m_state != ST_EXPRESSION_DONE && m_state != ST_NEED_EXPRESSION)
			{
				throw sinsp_exception("unexpected 'not' after " + m_fltstr.substr(0, m_scanpos));
			}

			m_state = ST_NEED_EXPRESSION;

			break;
		default:
			if(m_state == ST_NEED_EXPRESSION)
			{
				parse_check();

				m_state = ST_EXPRESSION_DONE;
			}
			else
			{
				throw sinsp_exception("syntax error in filter at position " + to_string((long long) m_scanpos));
			}
			break;
		}
	}

	vector<string> components = sinsp_split(m_fltstr, ' ');
	return m_filter;
}

sinsp_evttype_filter::sinsp_evttype_filter()
{
	memset(m_filter_by_evttype, 0, PPM_EVENT_MAX * sizeof(list<sinsp_filter *> *));
}

sinsp_evttype_filter::~sinsp_evttype_filter()
{
	for(int i = 0; i < PPM_EVENT_MAX; i++)
	{
		if(m_filter_by_evttype[i])
		{
			delete m_filter_by_evttype[i];
			m_filter_by_evttype[i] = NULL;
		}
	}

	m_catchall_evttype_filters.clear();

	for(const auto &val : m_evttype_filters)
	{
		delete val.second->filter;
		delete val.second;
	}
	m_evttype_filters.clear();
}

sinsp_evttype_filter::filter_wrapper::filter_wrapper()
	: enabled{true}
{
}

sinsp_evttype_filter::filter_wrapper::~filter_wrapper()
{
}

void sinsp_evttype_filter::add(string &name,
			       set<uint32_t> &evttypes,
			       set<string> &tags,
			       sinsp_filter *filter)
{
	filter_wrapper *wrap = new filter_wrapper();
	wrap->filter = filter;
	wrap->evttypes = evttypes;

	m_evttype_filters.insert(pair<string,filter_wrapper *>(name, wrap));

	if(evttypes.size() == 0)
	{
		m_catchall_evttype_filters.push_back(wrap);
	}
	else
	{

		for(const auto &evttype: evttypes)
		{
			list<filter_wrapper *> *filters = m_filter_by_evttype[evttype];
			if(filters == NULL)
			{
				filters = new list<filter_wrapper*>();
				m_filter_by_evttype[evttype] = filters;
			}

			filters->push_back(wrap);
		}
	}

	for(const auto &tag: tags)
	{
		auto it = m_filter_by_tag.lower_bound(tag);

		if(it == m_filter_by_tag.end() ||
		   it->first != tag)
		{
			it = m_filter_by_tag.emplace_hint(it,
							  std::make_pair(tag, std::list<filter_wrapper*>()));
		}

		it->second.push_back(wrap);
	}
}

void sinsp_evttype_filter::enable(const string &pattern, bool enabled, uint16_t ruleset)
{
	regex re(pattern);

	for(const auto &val : m_evttype_filters)
	{
		if (regex_match(val.first, re))
		{
			if(val.second->enabled.size() < (size_t) (ruleset + 1))
			{
				val.second->enabled.resize(ruleset + 1);
			}
			val.second->enabled[ruleset] = enabled;
		}
	}
}

void sinsp_evttype_filter::enable_tags(const set<string> &tags, bool enabled, uint16_t ruleset)
{
	for(const auto &tag : tags)
	{
		for(const auto &wrap : m_filter_by_tag[tag])
		{
			if(wrap->enabled.size() < (size_t) (ruleset + 1))
			{
				wrap->enabled.resize(ruleset + 1);
			}
			wrap->enabled[ruleset] = enabled;
		}
	}
}

bool sinsp_evttype_filter::run(sinsp_evt *evt, uint16_t ruleset)
{
	//
	// First run any catchall event type filters (ones that did not
	// explicitly specify any event type.
	//
	for(filter_wrapper *wrap : m_catchall_evttype_filters)
	{
		if(wrap->enabled.size() >= (size_t) (ruleset + 1) &&
		   wrap->enabled[ruleset] &&
		   wrap->filter->run(evt))
		{
			return true;
		}
	}

        list<filter_wrapper *> *filters = m_filter_by_evttype[evt->m_pevt->type];

	if(filters)
	{
		for(filter_wrapper *wrap : *filters)
		{
			if(wrap->enabled.size() >= (size_t) (ruleset + 1) &&
			   wrap->enabled[ruleset] &&
			   wrap->filter->run(evt))
			{
				return true;
			}
		}
	}

	return false;
}
#endif // HAS_FILTERING
