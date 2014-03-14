/*
Copyright (C) 2013-2014 Draios inc.
 
This file is part of sysdig.

sysdig is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

sysdig is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with sysdig.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _WIN32
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <sys/socket.h>
#include <algorithm>
#endif

#include "sinsp.h"
#include "sinsp_int.h"

#include "../libscap/scap.h"

extern sinsp_evttables g_infotables;

///////////////////////////////////////////////////////////////////////////////
// sinsp_evt_param implementation
///////////////////////////////////////////////////////////////////////////////
void sinsp_evt_param::init(char *valptr, uint16_t len)
{
	m_val = valptr;
	m_len = len;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_evt implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_evt::sinsp_evt() :
	m_paramstr_storage(256), m_resolved_paramstr_storage(1024)
{
	m_params_loaded = false;
	m_tinfo = NULL;
#ifdef _DEBUG
	m_filtered_out = false;
#endif
}

sinsp_evt::sinsp_evt(sinsp *inspector) :
	m_paramstr_storage(1024), m_resolved_paramstr_storage(1024)
{
	m_inspector = inspector;
	m_params_loaded = false;
	m_tinfo = NULL;
#ifdef _DEBUG
	m_filtered_out = false;
#endif
}

sinsp_evt::~sinsp_evt()
{
}

void sinsp_evt::init()
{
	m_params_loaded = false;
	m_info = scap_event_getinfo(m_pevt);
	m_tinfo = NULL;
	m_fdinfo = NULL;
	m_iosize = 0;
}

void sinsp_evt::init(uint8_t *evdata, uint16_t cpuid)
{
	m_params_loaded = false;
	m_pevt = (scap_evt *)evdata;
	m_info = scap_event_getinfo(m_pevt);
	m_tinfo = NULL;
	m_fdinfo = NULL;
	m_iosize = 0;
	m_cpuid = cpuid;
	m_evtnum = 0;
}

uint64_t sinsp_evt::get_num()
{
	return m_evtnum;
}

int16_t sinsp_evt::get_cpuid()
{
	return m_cpuid;
}

uint16_t sinsp_evt::get_type()
{
	return m_pevt->type;
}

ppm_event_flags sinsp_evt::get_flags()
{
	return m_info->flags;
}

uint64_t sinsp_evt::get_ts()
{
	return m_pevt->ts;
}

const char *sinsp_evt::get_name()
{
	return m_info->name;
}

event_direction sinsp_evt::get_direction()
{
	return (event_direction)(m_pevt->type & PPME_DIRECTION_FLAG);
}

int64_t sinsp_evt::get_tid()
{
	return m_pevt->tid;
}

void sinsp_evt::set_iosize(uint32_t size)
{
	m_iosize = size;
}

uint32_t sinsp_evt::get_iosize()
{
	return m_iosize;
}

sinsp_threadinfo* sinsp_evt::get_thread_info(bool query_os_if_not_found)
{
	if(NULL != m_tinfo)
	{
		return m_tinfo;
	}

	return m_inspector->get_thread(m_pevt->tid, query_os_if_not_found);
}

sinsp_fdinfo_t* sinsp_evt::get_fd_info()
{
	return m_fdinfo;
}

uint64_t sinsp_evt::get_fd_num()
{
	if(m_fdinfo)
	{
		return m_tinfo->m_lastevent_fd;
	}
	else
	{
		return sinsp_evt::INVALID_FD_NUM;
	}
}


uint32_t sinsp_evt::get_num_params()
{
	if(!m_params_loaded)
	{
		load_params();
		m_params_loaded = true;
	}

	return m_params.size();
}

sinsp_evt_param *sinsp_evt::get_param(uint32_t id)
{
	if(!m_params_loaded)
	{
		load_params();
		m_params_loaded = true;
	}

	return &(m_params[id]);
}

const char *sinsp_evt::get_param_name(uint32_t id)
{
	if(!m_params_loaded)
	{
		load_params();
		m_params_loaded = true;
	}

	ASSERT(id < m_info->nparams);

	return m_info->params[id].name;
}

const struct ppm_param_info* sinsp_evt::get_param_info(uint32_t id)
{
	if(!m_params_loaded)
	{
		load_params();
		m_params_loaded = true;
	}

	ASSERT(id < m_info->nparams);

	return &(m_info->params[id]);
}

uint32_t binary_buffer_to_hex_string(char *dst, char *src, uint32_t dstlen, uint32_t srclen, sinsp_evt::param_fmt fmt)
{
	uint32_t j;
	uint32_t k;
	uint32_t l = 0;
	uint32_t num_chunks;
	uint32_t row_len;
	char row[128];
	char *ptr;

	for(j = 0; j < srclen; j += 8 * sizeof(uint16_t))
	{
		k = 0;
		k += sprintf(row + k, "\n\t0x%.4x:", j);

		ptr = &src[j];
		num_chunks = 0;
		while(num_chunks < 8 && ptr < src + srclen)
		{
			uint16_t* chunk = (uint16_t*)ptr;
			if(ptr == src + srclen - 1)
			{
				k += sprintf(row + k, "   %.2x", *((uint8_t*)chunk));
			}
			else
			{
				k += sprintf(row + k, " %.4x", *chunk);
			}

			num_chunks++;
			ptr += sizeof(uint16_t);
		}

		if(fmt == sinsp_evt::PF_HEXASCII)
		{
			// Fill the row with spaces to align it to other rows
			while(num_chunks < 8)
			{
				memset(row + k, ' ', 5);

				k += 5;
				num_chunks++;
			}

			row[k++] = ' ';
			row[k++] = ' ';

			for(ptr = &src[j];
				ptr < src + j + 8 * sizeof(uint16_t) && ptr < src + srclen;
				ptr++, k++)
			{
				if(isprint((int)(uint8_t)*ptr))
				{
					row[k] = *ptr;
				}
				else
				{
					row[k] = '.';
				}
			}
		}
		row[k] = 0;

		row_len = strlen(row);
		if(l + row_len >= dstlen - 1)
		{
			break;
		}
		strcpy(dst + l, row);
		l += row_len;
	}

	dst[l++] = '\n';
	return l;
}

uint32_t binary_buffer_to_string(char *dst, char *src, uint32_t dstlen, uint32_t srclen, sinsp_evt::param_fmt fmt)
{
	uint32_t j;
	uint32_t k = 0;

	if(dstlen == 0)
	{
		ASSERT(false);
		return 0;
	}

	if(srclen == 0)
	{
		*dst = 0;
		return 0;
	}

	if(fmt == sinsp_evt::PF_HEX || fmt == sinsp_evt::PF_HEXASCII)
	{
		k = binary_buffer_to_hex_string(dst, src, dstlen, srclen, fmt);
	}
	else
	{
		for(j = 0; j < srclen; j++)
		{
			//
			// Make sure there's enough space in the target buffer.
			// Note that we reserve two bytes, because some characters are expanded
			// when copied.
			//
			if(k >= dstlen - 1)
			{
				dst[k - 1] = 0;
				return k - 1;
			}

			if(isprint((int)(uint8_t)src[j]))
			{
				switch(src[j])
				{
				case '"':
				case '\\':
					dst[k++] = '\\';
					break;
				default:
					break;
				}

				dst[k] = src[j];
			}
			else
			{
				dst[k] = '.';
			}

			k++;
		}
	}

	dst[k] = 0;
	return k;
}

uint32_t strcpy_sanitized(char *dest, char *src, uint32_t dstsize)
{
	volatile char* tmp = (volatile char *)dest;
	size_t j = 0;
	g_invalidchar ic;

	while(j < dstsize)
	{
		if(!ic(*src))
		{
			*tmp = *src;
			tmp++;
			j++;
		}

		if(*src == 0)
		{
			*tmp = 0;
			return j + 1;
		}

		src++;
	}

	//
	// In case there wasn't enough space, null-termninate the destination
	//
	if(dstsize)
	{
		dest[dstsize - 1] = 0;
	}

	return dstsize;
}

const char* sinsp_evt::get_param_as_str(uint32_t id, OUT const char** resolved_str, sinsp_evt::param_fmt fmt)
{
	uint32_t j;
	ASSERT(id < m_info->nparams);

	//
	// Make sure the params are actually loaded
	//
	if(!m_params_loaded)
	{
		load_params();
		m_params_loaded = true;
	}

	//
	// Reset the resolved string
	//
	*resolved_str = &m_resolved_paramstr_storage[0];
	m_resolved_paramstr_storage[0] = 0;

	//
	// Get the parameter
	//
	sinsp_evt_param *param = &(m_params[id]);

	switch(m_info->params[id].type)
	{
	case PT_INT8:
		ASSERT(param->m_len == sizeof(int8_t));
		snprintf(&m_paramstr_storage[0],
			m_paramstr_storage.size(),
			"%" PRId8, *(int8_t *)param->m_val);
		break;
	case PT_INT16:
		ASSERT(param->m_len == sizeof(int16_t));
		snprintf(&m_paramstr_storage[0],
			m_paramstr_storage.size(),
			"%" PRId16, *(int16_t *)param->m_val);
		break;
	case PT_INT32:
		ASSERT(param->m_len == sizeof(int32_t));
		snprintf(&m_paramstr_storage[0],
			m_paramstr_storage.size(),
			"%" PRId32, *(int32_t *)param->m_val);
		break;
	case PT_INT64:
		ASSERT(param->m_len == sizeof(int64_t));
		snprintf(&m_paramstr_storage[0],
			m_paramstr_storage.size(),
			"%" PRId64, *(int64_t *)param->m_val);
		break;
	case PT_FD:
		{
		int64_t fd;
		ASSERT(param->m_len == sizeof(int64_t));

		fd = *(int64_t*)param->m_val;

		//
		// Add the fd number
		//
		snprintf(&m_paramstr_storage[0],
		         m_paramstr_storage.size(),
		         "%" PRId64, fd);

		sinsp_threadinfo* tinfo = get_thread_info();
		if(tinfo == NULL)
		{
			//
			// no thread. Definitely can't resolve the fd, just return the number
			//
			break;
		}

		if(fd >= 0)
		{
			sinsp_fdinfo_t *fdinfo = tinfo->get_fd(fd);
			if(fdinfo)
			{
				char tch = fdinfo->get_typechar();
				char ipprotoch = 0;
				
				if(fdinfo->m_type == SCAP_FD_IPV4_SOCK ||
					fdinfo->m_type == SCAP_FD_IPV6_SOCK ||
					fdinfo->m_type == SCAP_FD_IPV4_SERVSOCK ||
					fdinfo->m_type == SCAP_FD_IPV6_SERVSOCK)
				{
					scap_l4_proto l4p = fdinfo->get_l4proto();

					switch(l4p)
					{
					case SCAP_L4_TCP:
						ipprotoch = 't';
						break;
					case SCAP_L4_UDP:
						ipprotoch = 'u';
						break;
					case SCAP_L4_ICMP:
						ipprotoch = 'i';
						break;
					case SCAP_L4_RAW:
						ipprotoch = 'r';
						break;
					default:
						break;
					}
				}

				char typestr[3] =
				{
					(fmt == PF_SIMPLE)?(char)0:tch,
					ipprotoch,
					0
				};

				//
				// Make sure we remove invalid characters from the resolved name
				//
				string sanitized_str = fdinfo->m_name;

				sanitized_str.erase(remove_if(sanitized_str.begin(), sanitized_str.end(), g_invalidchar()), sanitized_str.end());

				//
				// Make sure the string will fit
				//
				if(sanitized_str.size() >= m_resolved_paramstr_storage.size())
				{
					m_resolved_paramstr_storage.resize(sanitized_str.size() + 1);
				}

				snprintf(&m_resolved_paramstr_storage[0],
					m_resolved_paramstr_storage.size(),
					"<%s>%s", typestr, sanitized_str.c_str());

/* XXX
				if(sanitized_str.length() == 0)
				{
					snprintf(&m_resolved_paramstr_storage[0],
							 m_resolved_paramstr_storage.size(),
							 "<%c>", tch);
				}
				else
				{
					snprintf(&m_resolved_paramstr_storage[0],
							 m_resolved_paramstr_storage.size(),
							 "%s", sanitized_str.c_str());
				}
*/
			}
		}
		else
		{
			//
			// Resolve this as an errno
			//
			string errstr(sinsp_utils::errno_to_str((int32_t)fd));
			if(errstr != "")
			{
				snprintf(&m_resolved_paramstr_storage[0],
				         m_resolved_paramstr_storage.size(),
				         "%s", errstr.c_str());
			}
		}
	}
	break;
	case PT_PID:
		{
			ASSERT(param->m_len == sizeof(int64_t));

			snprintf(&m_paramstr_storage[0],
					 m_paramstr_storage.size(),
					 "%" PRId64, *(int64_t *)param->m_val);


			sinsp_threadinfo* atinfo = m_inspector->get_thread(*(int64_t *)param->m_val, false);
			if(atinfo != NULL)
			{
				string& tcomm = atinfo->m_comm;

				//
				// Make sure the string will fit
				//
				if(tcomm.size() >= m_resolved_paramstr_storage.size())
				{
					m_resolved_paramstr_storage.resize(tcomm.size() + 1);
				}

				snprintf(&m_resolved_paramstr_storage[0],
						 m_resolved_paramstr_storage.size(),
						 "%s",
						 tcomm.c_str());
			}
		}
		break;
	case PT_UINT8:
		ASSERT(param->m_len == sizeof(uint8_t));
		snprintf(&m_paramstr_storage[0],
		         m_paramstr_storage.size(),
		         "%" PRIu8, *(uint8_t *)param->m_val);
		break;
	case PT_UINT16:
		ASSERT(param->m_len == sizeof(uint16_t));
		snprintf(&m_paramstr_storage[0],
		         m_paramstr_storage.size(),
		         "%" PRIu16, *(uint16_t *)param->m_val);
		break;
	case PT_UINT32:
		ASSERT(param->m_len == sizeof(uint32_t));
		snprintf(&m_paramstr_storage[0],
		         m_paramstr_storage.size(),
		         "%" PRIu32, *(uint32_t *)param->m_val);
		break;
	case PT_ERRNO:
	{
		ASSERT(param->m_len == sizeof(int64_t));

		int64_t val = *(int64_t *)param->m_val;

		snprintf(&m_paramstr_storage[0],
		         m_paramstr_storage.size(),
		         "%" PRId64, val);

		//
		// Resolve this as an errno
		//
		string errstr;

		if(val < 0)
		{
			errstr = sinsp_utils::errno_to_str((int32_t)val);

			if(errstr != "")
			{
				snprintf(&m_resolved_paramstr_storage[0],
				         m_resolved_paramstr_storage.size(),
				         "%s", errstr.c_str());
			}
		}
	}
	break;
	case PT_UINT64:
		ASSERT(param->m_len == sizeof(uint64_t));
		snprintf(&m_paramstr_storage[0],
		         m_paramstr_storage.size(),
		         "%" PRIu64, *(int64_t *)param->m_val);
		break;
	case PT_CHARBUF:
		//
		// Make sure the string will fit
		//
		if(param->m_len > m_resolved_paramstr_storage.size())
		{
			m_resolved_paramstr_storage.resize(param->m_len);
		}

		snprintf(&m_paramstr_storage[0],
		         m_paramstr_storage.size(),
		         "%s", param->m_val);
		break;
	case PT_FSPATH:
	{
		strcpy_sanitized(&m_paramstr_storage[0],
			param->m_val,
			MIN(param->m_len, m_paramstr_storage.size()));

		sinsp_threadinfo* tinfo = get_thread_info();

		if(tinfo)
		{
			string fullpath;
			string cwd = tinfo->get_cwd();

			if(!sinsp_utils::concatenate_paths(&m_resolved_paramstr_storage[0],
				m_resolved_paramstr_storage.size(),
				(char*)cwd.c_str(), 
				cwd.length(), 
				param->m_val, 
				param->m_len))
			{
				m_resolved_paramstr_storage[0] = 0;
			}
		}
		else
		{
			*resolved_str = &m_paramstr_storage[0];
		}
	}
	break;
	case PT_BYTEBUF:
	{
		/* This would include quotes around the outpur string
		            m_paramstr_storage[0] = '"';
		            cres = binary_buffer_to_string(m_paramstr_storage + 1,
		                param->m_val,
		                m_paramstr_storage.size() - 2,
		                param->m_len);

		            m_paramstr_storage[cres + 1] = '"';
		            m_paramstr_storage[cres + 2] = 0;
		*/
		if(binary_buffer_to_string(&m_paramstr_storage[0],
			param->m_val,
			m_paramstr_storage.size() - 1,
			param->m_len,
			fmt) == m_paramstr_storage.size())
		{
			//
			// The buffer didn't fit, expand it for future use
			//
			m_paramstr_storage.resize(m_paramstr_storage.size() * 2);
		}
	}
	break;
	case PT_SOCKADDR:
		if(param->m_len == 0)
		{
			snprintf(&m_paramstr_storage[0],
			         m_paramstr_storage.size(),
			         "NULL");

			break;
		}
		else if(param->m_val[0] == AF_UNIX)
		{
			ASSERT(param->m_len > 1);

			//
			// Sanitize the file string.
			//
            string sanitized_str = param->m_val + 1;
            sanitized_str.erase(remove_if(sanitized_str.begin(), sanitized_str.end(), g_invalidchar()), sanitized_str.end());

			snprintf(&m_paramstr_storage[0],
				m_paramstr_storage.size(), 
				"%s",
				sanitized_str.c_str());
		}
		else if(param->m_val[0] == PPM_AF_INET)
		{
			if(param->m_len == 1 + 4 + 2)
			{
				snprintf(&m_paramstr_storage[0],
				         m_paramstr_storage.size(),
				         "%u.%u.%u.%u:%u",
				         (unsigned int)(uint8_t)param->m_val[1],
				         (unsigned int)(uint8_t)param->m_val[2],
				         (unsigned int)(uint8_t)param->m_val[3],
				         (unsigned int)(uint8_t)param->m_val[4],
				         (unsigned int)*(uint16_t*)(param->m_val+5));
			}
			else
			{
				ASSERT(false);
				snprintf(&m_paramstr_storage[0],
				         m_paramstr_storage.size(),
				         "INVALID IPv4");
			}
		}
		else
		{
			snprintf(&m_paramstr_storage[0],
			         m_paramstr_storage.size(),
			         "family %d", (int)param->m_val[0]);
		}
		break;
	case PT_SOCKTUPLE:
		if(param->m_len == 0)
		{
			snprintf(&m_paramstr_storage[0],
			         m_paramstr_storage.size(),
			         "NULL");

			break;
		}
		
		if(param->m_val[0] == PPM_AF_INET)
		{
			if(param->m_len == 1 + 4 + 2 + 4 + 2)
			{
				snprintf(&m_paramstr_storage[0],
				         m_paramstr_storage.size(),
				         "%u.%u.%u.%u:%u->%u.%u.%u.%u:%u",
				         (unsigned int)(uint8_t)param->m_val[1],
				         (unsigned int)(uint8_t)param->m_val[2],
				         (unsigned int)(uint8_t)param->m_val[3],
				         (unsigned int)(uint8_t)param->m_val[4],
				         (unsigned int)*(uint16_t*)(param->m_val+5),
				         (unsigned int)(uint8_t)param->m_val[7],
				         (unsigned int)(uint8_t)param->m_val[8],
				         (unsigned int)(uint8_t)param->m_val[9],
				         (unsigned int)(uint8_t)param->m_val[10],
				         (unsigned int)*(uint16_t*)(param->m_val+11));
			}
			else
			{
				ASSERT(false);
				snprintf(&m_paramstr_storage[0],
				         m_paramstr_storage.size(),
				         "INVALID IPv4");
			}
		}
		else if(param->m_val[0] == PPM_AF_INET6)
		{
			if(param->m_len == 1 + 16 + 2 + 16 + 2)
			{
				uint8_t* sip6 = (uint8_t*)param->m_val + 1;
				uint8_t* dip6 = (uint8_t*)param->m_val + 19;
				uint8_t* sip = (uint8_t*)param->m_val + 13;
				uint8_t* dip = (uint8_t*)param->m_val + 31;

				if(sinsp_utils::is_ipv4_mapped_ipv6(sip6) && sinsp_utils::is_ipv4_mapped_ipv6(dip6))
				{
					snprintf(&m_paramstr_storage[0],
							 m_paramstr_storage.size(),
							 "%u.%u.%u.%u:%u->%u.%u.%u.%u:%u",
							 (unsigned int)sip[0],
							 (unsigned int)sip[1],
							 (unsigned int)sip[2],
							 (unsigned int)sip[3],
							 (unsigned int)*(uint16_t*)(param->m_val + 17),
							 (unsigned int)dip[0],
							 (unsigned int)dip[1],
							 (unsigned int)dip[2],
							 (unsigned int)dip[3],
							 (unsigned int)*(uint16_t*)(param->m_val + 35));
					break;
				}
				else
				{
					char srcstr[INET6_ADDRSTRLEN];
					char dststr[INET6_ADDRSTRLEN];
					if(inet_ntop(AF_INET6, sip6, srcstr, sizeof(srcstr)) && 
						inet_ntop(AF_INET6, sip6, dststr, sizeof(dststr)))
					{
						snprintf(&m_paramstr_storage[0],
								 m_paramstr_storage.size(),
								 "%s:%u->%s:%u",
								 srcstr,
								 (unsigned int)*(uint16_t*)(param->m_val + 17),
								 dststr,
								 (unsigned int)*(uint16_t*)(param->m_val + 35));
						break;
					}
				}
			}

			ASSERT(false);
			snprintf(&m_paramstr_storage[0],
				        m_paramstr_storage.size(),
				        "INVALID IPv6");
		}
		else if(param->m_val[0] == AF_UNIX)
		{
			ASSERT(param->m_len > 17);

			//
			// Sanitize the file string.
			//
            string sanitized_str = param->m_val + 17;
            sanitized_str.erase(remove_if(sanitized_str.begin(), sanitized_str.end(), g_invalidchar()), sanitized_str.end());

			snprintf(&m_paramstr_storage[0],
				m_paramstr_storage.size(), 
				"%" PRIx64 "->%" PRIx64 " %s", 
				*(uint64_t*)(param->m_val + 1),
				*(uint64_t*)(param->m_val + 9),
				sanitized_str.c_str());
		}
		else
		{
			snprintf(&m_paramstr_storage[0],
			         m_paramstr_storage.size(),
			         "family %d", (int)param->m_val[0]);
		}
		break;
	case PT_FDLIST:
		{
			sinsp_threadinfo* tinfo = get_thread_info();
			if(!tinfo)
			{
				break;
			}

			uint16_t nfds = *(uint16_t *)param->m_val;
			uint32_t pos = 2;
			uint32_t spos = 0;

			m_paramstr_storage[0] = 0;

			for(j = 0; j < nfds; j++)
			{
				char tch;
				int64_t fd = *(int64_t *)(param->m_val + pos);

				sinsp_fdinfo_t *fdinfo = tinfo->get_fd(fd);
				if(fdinfo)
				{
					tch = fdinfo->get_typechar();
				}
				else
				{
					tch = '?';
				}

				spos += snprintf(&m_paramstr_storage[0] + spos,
								 m_paramstr_storage.size() - spos,
								 "%" PRIu64 ":%c%x%c",
								 fd,
								 tch,
								 (uint32_t) * (int16_t *)(param->m_val + pos + 8),
								 (j < (uint32_t)(nfds - 1)) ? ' ' : '\0');

				if(spos < 0)
				{
					m_paramstr_storage[m_paramstr_storage.size() - 1] = 0;
					break;
				}

				pos += 10;
			}
		}
		break;
	case PT_SYSCALLID:
		{
			uint16_t scid  = *(uint16_t *)param->m_val;
			if(scid >= PPM_SC_MAX)
			{
				ASSERT(false);
				snprintf(&m_paramstr_storage[0],
						 m_paramstr_storage.size(),
						 "<unknown syscall>");
				break;
			}

			const struct ppm_syscall_desc* desc = &(g_infotables.m_syscall_info_table[scid]);

			snprintf(&m_paramstr_storage[0],
				m_paramstr_storage.size(),
				"%" PRIu16,
				scid);

			snprintf(&m_resolved_paramstr_storage[0],
				m_resolved_paramstr_storage.size(),
				"%s",
				desc->name);
		}
		break;
	case PT_SIGTYPE:
		{
			const char* sigstr;

			ASSERT(param->m_len == sizeof(uint8_t));
			uint8_t val = *(uint8_t *)param->m_val;

			sigstr = sinsp_utils::signal_to_str(val);

			snprintf(&m_paramstr_storage[0],
					 m_paramstr_storage.size(),
					 "%" PRIu8, val);

			if(sigstr)
			{
				snprintf(&m_resolved_paramstr_storage[0],
							m_resolved_paramstr_storage.size(),
							"%s", sigstr);
			}
		}
		break;
	case PT_RELTIME:
		{
			string sigstr;

			ASSERT(param->m_len == sizeof(uint64_t));
			uint64_t val = *(uint64_t *)param->m_val;

			snprintf(&m_paramstr_storage[0],
					 m_paramstr_storage.size(),
					 "%" PRIu64, val);

			snprintf(&m_resolved_paramstr_storage[0],
						m_resolved_paramstr_storage.size(),
						"%lgs", 
						((double)val) / 1000000000);
		}
		break;
	case PT_FLAGS8:
	case PT_FLAGS16:
	case PT_FLAGS32:
		{
			uint32_t val = *(uint32_t *)param->m_val & (((uint64_t)1 << param->m_len * 8) - 1);
			snprintf(&m_paramstr_storage[0],
				     m_paramstr_storage.size(),
				     "%" PRIu32, val);

			const struct ppm_name_value *flags = m_info->params[id].symbols;
			const char *separator = "";
			uint32_t initial_val = val;
			uint32_t j = 0;

			while(flags != NULL && flags->name != NULL && flags->value != initial_val)
			{
				if((val & flags->value) == flags->value && val != 0)
				{
					if(m_resolved_paramstr_storage.size() < j + strlen(separator) + strlen(flags->name))
					{
						m_resolved_paramstr_storage.resize(m_resolved_paramstr_storage.size() * 2);
					}

					j += snprintf(&m_resolved_paramstr_storage[j],
								  m_resolved_paramstr_storage.size(),
							 	  "%s%s",
							 	  separator,
							 	  flags->name);

					separator = "|";
					// We remove current flags value to avoid duplicate flags e.g. PPM_O_RDWR, PPM_O_RDONLY, PPM_O_WRONLY
					val &= ~flags->value;
				}

				flags++;
			}

			if(flags != NULL && flags->name != NULL)
			{
				j += snprintf(&m_resolved_paramstr_storage[j],
							  m_resolved_paramstr_storage.size(),
							  "%s%s",
							  separator,
							  flags->name);
			}

			break;
		}
	case PT_ABSTIME:
		//
		// XXX not implemented yet
		//
		ASSERT(false);
	default:
		ASSERT(false);
		snprintf(&m_paramstr_storage[0],
		         m_paramstr_storage.size(),
		         "(n.a.)");
		break;
	}

	return &m_paramstr_storage[0];
}

string sinsp_evt::get_param_value_str(string &name, bool resolved)
{
	for(uint32_t i = 0; i < get_num_params(); i++)
	{
		if(name == get_param_name(i))
		{
			return get_param_value_str(i, resolved);
		}
	}

	return string("");
}

string sinsp_evt::get_param_value_str(const char *name, bool resolved)
{
	// TODO fix this !!
	string s_name = string(name);
	return get_param_value_str(s_name, resolved);
}

string sinsp_evt::get_param_value_str(uint32_t i, bool resolved)
{
	const char *param_value_str;
	const char *val_str;
	val_str = get_param_as_str(i, &param_value_str);

	if(resolved)
	{
		return string((*param_value_str == '\0')? val_str : param_value_str);
	}
	else
	{
		return string(val_str);
	}
}

const char* sinsp_evt::get_param_value_str(const char* name, OUT const char** resolved_str, param_fmt fmt)
{
	for(uint32_t i = 0; i < get_num_params(); i++)
	{
		if(strcmp(name, get_param_name(i)) == 0)
		{
			return get_param_as_str(i, resolved_str, fmt);
		}
	}

	*resolved_str = NULL;
	return NULL;
}

const sinsp_evt_param* sinsp_evt::get_param_value_raw(const char* name)
{
	//
	// Make sure the params are actually loaded
	//
	if(!m_params_loaded)
	{
		load_params();
		m_params_loaded = true;
	}

	//
	// Locate the parameter given the name
	//
	uint32_t np = get_num_params();

	for(uint32_t j = 0; j < np; j++)
	{
		if(strcmp(name, get_param_name(j)) == 0)
		{
			return &(m_params[j]);
		}
	}

	return NULL;
}

void sinsp_evt::load_params()
{
	uint32_t j;
	uint32_t nparams;
	sinsp_evt_param par;

	nparams = m_info->nparams;
	uint16_t *lens = (uint16_t *)((char *)m_pevt + sizeof(struct ppm_evt_hdr));
	char *valptr = (char *)lens + nparams * sizeof(uint16_t);
	m_params.clear();

	for(j = 0; j < nparams; j++)
	{
		par.init(valptr, lens[j]);
		m_params.push_back(par);
		valptr += lens[j];
	}
}

void sinsp_evt::get_category(OUT sinsp_evt::category* cat)
{
	if(get_type() == PPME_GENERIC_E || 
		get_type() == PPME_GENERIC_X)
	{
		//
		// This event is a syscall that doesn't have a filler yet.
		// The category can be found in g_syscall_info_table.
		//
		sinsp_evt_param *parinfo = get_param(0);
		ASSERT(parinfo->m_len == sizeof(uint16_t));
		uint16_t id = *(uint16_t *)parinfo->m_val;

		cat->m_category = g_infotables.m_syscall_info_table[id].category;
		cat->m_subcategory = sinsp_evt::SC_NONE;
	}
	else
	{
		//
		// This event has a real filler.
		// The category can be found in the info struct.
		//
		cat->m_category = m_info->category;

		//
		// For EC_IO and EC_WAIT events, we dig into the fd state to get the category
		// and fdtype
		//
		if(cat->m_category & EC_IO_BASE)
		{
			if(!m_fdinfo)
			{
				//
				// The fd info is not present, likely because we missed its creation.
				//
				cat->m_subcategory = SC_UNKNOWN;
				return;
			}
			else
			{
				switch(m_fdinfo->m_type)
				{
					case SCAP_FD_FILE:
					case SCAP_FD_DIRECTORY:
						cat->m_subcategory = SC_FILE;
						break;
					case SCAP_FD_IPV4_SOCK:
					case SCAP_FD_IPV6_SOCK:
						cat->m_subcategory = SC_NET;
					case SCAP_FD_IPV4_SERVSOCK:
					case SCAP_FD_IPV6_SERVSOCK:
						cat->m_subcategory = SC_NET;
						break;
					case SCAP_FD_FIFO:
					case SCAP_FD_UNIX_SOCK:
					case SCAP_FD_EVENT:
					case SCAP_FD_SIGNALFD:
					case SCAP_FD_INOTIFY:
						cat->m_subcategory = SC_IPC;
						break;
					case SCAP_FD_UNSUPPORTED:
					case SCAP_FD_EVENTPOLL:
					case SCAP_FD_TIMERFD:
						cat->m_subcategory = SC_OTHER;
						break;
					case SCAP_FD_UNKNOWN:
						cat->m_subcategory = SC_OTHER;
						break;
					default:
						ASSERT(false);
						cat->m_subcategory = SC_UNKNOWN;
						break;
				}
			}
		}
		else
		{
			cat->m_subcategory = sinsp_evt::SC_NONE;
		}
	}
}
