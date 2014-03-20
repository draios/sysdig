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

#ifndef _WIN32
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#endif

#include "sinsp.h"
#include "sinsp_int.h"
#include "sinsp_errno.h"
#include "sinsp_signal.h"
#include "filter.h"
#include "filterchecks.h"

const chiseldir_info g_chisel_dirs_array[] =
{
	{false, ""}, // file as is
#ifdef _WIN32
	{false, "c:/sysdig/chisels/"},
#endif
	{false, "./"},
	{false, "./chisels/"},
	{true, "~/chisels/"},
};

#ifndef _WIN32
char* realpath_ex(const char *path, char *buff) 
{
    char *home;

    if(*path=='~' && (home = getenv("HOME"))) 
    {
        char s[PATH_MAX];
        return realpath(strcat(strcpy(s, home), path+1), buff);
    } 
    else 
    {
        return realpath(path, buff);
    }
}
#endif

///////////////////////////////////////////////////////////////////////////////
// sinsp_initializer implementation
///////////////////////////////////////////////////////////////////////////////

//
// These are the libsinsp globals
//
sinsp_evttables g_infotables;
sinsp_logger g_logger;
sinsp_initializer g_initializer;
#ifdef HAS_FILTERING
sinsp_filter_check_list g_filterlist;
#endif
vector<chiseldir_info>* g_chisel_dirs = NULL;

//
// loading time initializations
//
sinsp_initializer::sinsp_initializer()
{
	//
	// Init the event tables
	//
	g_infotables.m_event_info = scap_get_event_info_table();
	g_infotables.m_syscall_info_table = scap_get_syscall_info_table();

	//
	// Init the logger
	//
	g_logger.set_severity(sinsp_logger::SEV_DEBUG);

	//
	// Init the chisel directory list
	//
	g_chisel_dirs = NULL;
	g_chisel_dirs = new vector<chiseldir_info>();

	for(uint32_t j = 0; j < sizeof(g_chisel_dirs_array) / sizeof(g_chisel_dirs_array[0]); j++)
	{
		if(g_chisel_dirs_array[j].m_need_to_resolve)
		{
#ifndef _WIN32
			char resolved_path[PATH_MAX];

			if(realpath_ex(g_chisel_dirs_array[j].m_dir, resolved_path) != NULL)
			{
				string resolved_path_str(resolved_path);

				if(resolved_path_str[resolved_path_str.size() -1] != '/')
				{
					resolved_path_str += "/";
				}

				chiseldir_info cdi;
				cdi.m_need_to_resolve = false;
				sprintf(cdi.m_dir, "%s", resolved_path_str.c_str());
				g_chisel_dirs->push_back(cdi);
			}
#else
			g_chisel_dirs->push_back(g_chisel_dirs_array[j]);
#endif
		}
		else
		{
			g_chisel_dirs->push_back(g_chisel_dirs_array[j]);
		}
	}

	//
	// Sockets initialization on windows
	//
#ifdef _WIN32
	WSADATA wsaData;
	WORD version = MAKEWORD( 2, 0 );
	WSAStartup( version, &wsaData );
#endif
}

sinsp_initializer::~sinsp_initializer()
{
	if(g_chisel_dirs)
	{
		delete g_chisel_dirs;
	}
}

///////////////////////////////////////////////////////////////////////////////
// Various helper functions
///////////////////////////////////////////////////////////////////////////////

//
// errno to string conversion.
// Only the first 40 error codes are currently implemented
//
const char* sinsp_utils::errno_to_str(int32_t code)
{
	switch(-code)
	{
	case SE_EPERM:
		return "EPERM";
	case SE_ENOENT:
		return "ENOENT";
	case SE_ESRCH:
		return "ESRCH";
	case SE_EINTR:
		return "EINTR";
	case SE_EIO:
		return "EIO";
	case SE_ENXIO:
		return "ENXIO";
	case SE_E2BIG:
		return "E2BIG";
	case SE_ENOEXEC:
		return "ENOEXEC";
	case SE_EBADF:
		return "EBADF";
	case SE_ECHILD:
		return "ECHILD";
	case SE_EAGAIN:
		return "EAGAIN";
	case SE_ENOMEM:
		return "ENOMEM";
	case SE_EACCES:
		return "EACCES";
	case SE_EFAULT:
		return "EFAULT";
	case SE_ENOTBLK:
		return "ENOTBLK";
	case SE_EBUSY:
		return "EBUSY";
	case SE_EEXIST:
		return "EEXIST";
	case SE_EXDEV:
		return "EXDEV";
	case SE_ENODEV:
		return "ENODEV";
	case SE_ENOTDIR:
		return "ENOTDIR";
	case SE_EISDIR:
		return "EISDIR";
	case SE_EINVAL:
		return "EINVAL";
	case SE_ENFILE:
		return "ENFILE";
	case SE_EMFILE:
		return "EMFILE";
	case SE_ENOTTY:
		return "ENOTTY";
	case SE_ETXTBSY:
		return "ETXTBSY";
	case SE_EFBIG:
		return "EFBIG";
	case SE_ENOSPC:
		return "ENOSPC";
	case SE_ESPIPE:
		return "ESPIPE";
	case SE_EROFS:
		return "EROFS";
	case SE_EMLINK:
		return "EMLINK";
	case SE_EPIPE:
		return "EPIPE";
	case SE_EDOM:
		return "EDOM";
	case SE_ERANGE:
		return "ERANGE";
	case SE_EDEADLK:
		return "EDEADLK";
	case SE_ENAMETOOLONG:
		return "ENAMETOOLONG";
	case SE_ENOLCK:
		return "ENOLCK";
	case SE_ENOSYS:
		return "ENOSYS";
	case SE_ENOTEMPTY:
		return "ENOTEMPTY";
	case SE_ELOOP:
		return "ELOOP";
	case SE_ERESTARTSYS:
		return "ERESTARTSYS";
	case SE_ENETUNREACH:
		return "ENETUNREACH";
	case SE_EINPROGRESS:
		return "EINPROGRESS";
	case SE_ETIMEDOUT:
		return "ETIMEDOUT";
	case SE_ECONNRESET:
		return "ECONNRESET";
	case SE_ECONNREFUSED:
		return "ECONNREFUSED";
	case SE_ERESTARTNOHAND:
		return "ERESTARTNOHAND";
	case SE_EADDRNOTAVAIL:
		return "EADDRNOTAVAIL";
	case SE_ENOTCONN:
		return "ENOTCONN";
	case SE_ENETDOWN:
		return "ENETDOWN";
	case SE_EOPNOTSUPP:
		return "EOPNOTSUPP";
	case SE_ENOTSOCK:
		return "ENOTSOCK";
	case SE_ERESTART_RESTARTBLOCK:
		return "ERESTART_RESTARTBLOCK";
	case SE_EADDRINUSE:
		return "EADDRINUSE";
	case SE_EPROTOTYPE:
		return "EPROTOTYPE";
	case SE_EALREADY:
		return "EALREADY";
	default:
		ASSERT(false);
		return "";
	}
}

//
// errno to string conversion.
// Only the first 40 error codes are currently implemented
//
const char* sinsp_utils::signal_to_str(uint8_t code)
{
	switch(code)
	{
	case SE_SIGHUP:
		return "SIGHUP";
	case SE_SIGINT:
		return "SIGINT";
	case SE_SIGQUIT:
		return "SIGQUIT";
	case SE_SIGILL:
		return "SIGILL";
	case SE_SIGTRAP:
		return "SIGTRAP";
	case SE_SIGABRT:
		return "SIGABRT";
	case SE_SIGBUS:
		return "SIGBUS";
	case SE_SIGFPE:
		return "SIGFPE";
	case SE_SIGKILL:
		return "SIGKILL";
	case SE_SIGUSR1:
		return "SIGUSR1";
	case SE_SIGSEGV:
		return "SIGSEGV";
	case SE_SIGUSR2:
		return "SIGUSR2";
	case SE_SIGPIPE:
		return "SIGPIPE";
	case SE_SIGALRM:
		return "SIGALRM";
	case SE_SIGTERM:
		return "SIGTERM";
	case SE_SIGSTKFLT:
		return "SIGSTKFLT";
	case SE_SIGCHLD:
		return "SIGCHLD";
	case SE_SIGCONT:
		return "SIGCONT";
	case SE_SIGSTOP:
		return "SIGSTOP";
	case SE_SIGTSTP:
		return "SIGTSTP";
	case SE_SIGTTIN:
		return "SIGTTIN";
	case SE_SIGTTOU:
		return "SIGTTOU";
	case SE_SIGURG:
		return "SIGURG";
	case SE_SIGXCPU:
		return "SIGXCPU";
	case SE_SIGXFSZ:
		return "SIGXFSZ";
	case SE_SIGVTALRM:
		return "SIGVTALRM";
	case SE_SIGPROF:
		return "SIGPROF";
	case SE_SIGWINCH:
		return "SIGWINCH";
	case SE_SIGIO:
		return "SIGIO";
	case SE_SIGPWR:
		return "SIGPWR";
	case SE_SIGSYS:
		return "SIGSYS";
	default:
		return NULL;
	}
}

bool sinsp_utils::sockinfo_to_str(sinsp_sockinfo* sinfo, scap_fd_type stype, char* targetbuf, uint32_t targetbuf_size)
{
	if(stype == SCAP_FD_IPV4_SOCK)
	{
		uint8_t* sb = (uint8_t*)&sinfo->m_ipv4info.m_fields.m_sip;
		uint8_t* db = (uint8_t*)&sinfo->m_ipv4info.m_fields.m_dip;

		if(sinfo->m_ipv4info.m_fields.m_l4proto == SCAP_L4_TCP ||
			sinfo->m_ipv4info.m_fields.m_l4proto == SCAP_L4_UDP)
		{
			snprintf(targetbuf,
				targetbuf_size,
				"%u.%u.%u.%u:%u->%u.%u.%u.%u:%u",
				(unsigned int)(uint8_t)sb[0],
				(unsigned int)(uint8_t)sb[1],
				(unsigned int)(uint8_t)sb[2],
				(unsigned int)(uint8_t)sb[3],
				(unsigned int)sinfo->m_ipv4info.m_fields.m_sport,
				(unsigned int)(uint8_t)db[0],
				(unsigned int)(uint8_t)db[1],
				(unsigned int)(uint8_t)db[2],
				(unsigned int)(uint8_t)db[3],
				(unsigned int)sinfo->m_ipv4info.m_fields.m_dport);
		}
		else if(sinfo->m_ipv4info.m_fields.m_l4proto == SCAP_L4_ICMP ||
			sinfo->m_ipv4info.m_fields.m_l4proto == SCAP_L4_RAW)
		{
			snprintf(targetbuf,
				targetbuf_size,
				"%u.%u.%u.%u->%u.%u.%u.%u",
				(unsigned int)(uint8_t)sb[0],
				(unsigned int)(uint8_t)sb[1],
				(unsigned int)(uint8_t)sb[2],
				(unsigned int)(uint8_t)sb[3],
				(unsigned int)(uint8_t)db[0],
				(unsigned int)(uint8_t)db[1],
				(unsigned int)(uint8_t)db[2],
				(unsigned int)(uint8_t)db[3]);
		}
		else
		{
			snprintf(targetbuf,
				targetbuf_size,
				"<unknown>");
		}
	}
	else if(stype == SCAP_FD_IPV6_SOCK)
	{
		uint8_t* sip6 = (uint8_t*)sinfo->m_ipv6info.m_fields.m_sip;
		uint8_t* dip6 = (uint8_t*)sinfo->m_ipv6info.m_fields.m_dip;
		uint8_t* sip = ((uint8_t*)(sinfo->m_ipv6info.m_fields.m_sip)) + 12;
		uint8_t* dip = ((uint8_t*)(sinfo->m_ipv6info.m_fields.m_dip)) + 12;

		if(sinfo->m_ipv6info.m_fields.m_l4proto == SCAP_L4_TCP ||
			sinfo->m_ipv6info.m_fields.m_l4proto == SCAP_L4_UDP)
		{
			if(sinsp_utils::is_ipv4_mapped_ipv6(sip6) && sinsp_utils::is_ipv4_mapped_ipv6(dip6))
			{
				snprintf(targetbuf,
							targetbuf_size,
							"%u.%u.%u.%u:%u->%u.%u.%u.%u:%u",
							(unsigned int)sip[0],
							(unsigned int)sip[1],
							(unsigned int)sip[2],
							(unsigned int)sip[3],
							(unsigned int)sinfo->m_ipv4info.m_fields.m_sport,
							(unsigned int)dip[0],
							(unsigned int)dip[1],
							(unsigned int)dip[2],
							(unsigned int)dip[3],
							(unsigned int)sinfo->m_ipv4info.m_fields.m_dport);
				return true;
			}
			else
			{
				char srcstr[INET6_ADDRSTRLEN];
				char dststr[INET6_ADDRSTRLEN];
				if(inet_ntop(AF_INET6, sip6, srcstr, sizeof(srcstr)) && 
					inet_ntop(AF_INET6, sip6, dststr, sizeof(dststr)))
				{
					snprintf(targetbuf,
								targetbuf_size,
								"%s:%u->%s:%u",
								srcstr,
								(unsigned int)sinfo->m_ipv4info.m_fields.m_sport,
								dststr,
								(unsigned int)sinfo->m_ipv4info.m_fields.m_dport);
					return true;
				}
			}
		}
		else if(sinfo->m_ipv6info.m_fields.m_l4proto == SCAP_L4_ICMP)
		{
			if(sinsp_utils::is_ipv4_mapped_ipv6(sip6) && sinsp_utils::is_ipv4_mapped_ipv6(dip6))
			{
				snprintf(targetbuf,
					targetbuf_size,
					"%u.%u.%u.%u->%u.%u.%u.%u",
					(unsigned int)sip[0],
					(unsigned int)sip[1],
					(unsigned int)sip[2],
					(unsigned int)sip[3],
					(unsigned int)dip[0],
					(unsigned int)dip[1],
					(unsigned int)dip[2],
					(unsigned int)dip[3]);

				return true;
			}
			else
			{
				char srcstr[INET6_ADDRSTRLEN];
				char dststr[INET6_ADDRSTRLEN];
				if(inet_ntop(AF_INET6, sip6, srcstr, sizeof(srcstr)) && 
					inet_ntop(AF_INET6, sip6, dststr, sizeof(dststr)))
				{
					snprintf(targetbuf,
						targetbuf_size,
						"%s->%s",
						srcstr,
						dststr);

					return true;
				}
			}
		}
		else
		{
			snprintf(targetbuf,
				targetbuf_size,
				"<unknown>");
		}
	}

	return true;
}

//
// Helper function to move a directory up in a path string
//
void rewind_to_parent_path(char* targetbase, char** tc, const char** pc, uint32_t delta)
{
	if(*tc <= targetbase + 1)
	{
		(*pc) += delta;
		return;
	}

	(*tc)--;

	while(*((*tc) - 1) != '/' && (*tc) >= targetbase + 1)
	{
		(*tc)--;
	}

	(*pc) += delta;
}

//
// Args:
//  - target: the string where we are supposed to start copying 
//  - targetbase: the base of the path, i.e. the furthest we can go back when 
//                following parent directories 
//  - path: the path to copy 
//
void copy_and_sanitize_path(char* target, char* targetbase, const char* path)
{
	char* tc = target;
	const char* pc = path;
	g_invalidchar ic;

	while(true)
	{
		if(*pc == 0)
		{
			*tc = 0;

			//
			// If the path ends with a '/', remove it, as the OS does.
			//
			if((tc > (targetbase + 1)) && (*(tc - 1) == '/'))
			{
				*(tc - 1) = 0;
			}

			return;
		}

		if(ic(*pc))
		{
			//
			// Invalid char, substitute with a '.'
			//
			*tc = '.';
			tc++;
			pc++;
		}
		else
		{
			if(*pc == '.' && *(pc + 1) == '.' && *(pc + 2) == '/')
			{
				//
				// '../', rewind to the previous '/'
				//
				rewind_to_parent_path(targetbase, &tc, &pc, 3);

			}
			else if(*pc == '.' && *(pc + 1) == '.')
			{
				//
				// '..', with no '/'.
				// This is valid if we are at the end of the string, and in that case we rewind.
				// Otherwise it shouldn't happen and we leave the string intact
				//
				if(*(pc + 2) == 0)
				{
					rewind_to_parent_path(targetbase, &tc, &pc, 2);
				}
				else
				{
					*tc = '.';
					*(tc + 1) = '.';
					pc += 2;
					tc += 2;
				}
			}
			else if(*pc == '.' && *(pc + 1) == '/')
			{
				//
				// './', just skip it
				//
				pc += 2;
			}
			else if(*pc == '.')
			{
				//
				// '.', with no '/'.
				// This is valid if we are at the end of the string, and in that case we rewind.
				// Otherwise it shouldn't happen and we leave the string intact
				//
				if(*(pc + 1) == 0)
				{
					pc++;
				}
				else
				{
					*tc = *pc;
					tc++;
					pc++;
				}
			}
			else if(*pc == '/')
			{
				//
				// '/', if the last char is already a '/', skip it
				//
				if(tc > targetbase && *(tc - 1) == '/')
				{
					pc++;
				}
				else
				{
					*tc = *pc;
					tc++;
					pc++;
				}
			}
			else
			{
				//
				// Normal char, copy it
				//
				*tc = *pc;
				tc++;
				pc++;
			}
		}
	}
}

//
// Return false if path2 is an absolute path
//
bool sinsp_utils::concatenate_paths(char* target, 
									uint32_t targetlen, 
									const char* path1, 
									uint32_t len1, 
									const char* path2, 
									uint32_t len2)
{
	if(targetlen < (len1 + len2 + 1))
	{
		ASSERT(false);
		strcpy(target, "/PATH_TOO_LONG");
	}

	if(len2 != 0 && path2[0] != '/')
	{
		memcpy(target, path1, len1);
		copy_and_sanitize_path(target + len1, target, path2);
		return true;
	}
	else
	{
		target[0] = 0;
		copy_and_sanitize_path(target, target, path2);
		return false;
	}
}

bool sinsp_utils::is_ipv4_mapped_ipv6(uint8_t* paddr)
{
	if(paddr[0] == 0 && paddr[1] == 0 && paddr[2] == 0 && paddr[3] == 0 && paddr[4] == 0 && 
		paddr[5] == 0 && paddr[6] == 0 && paddr[7] == 0 && paddr[8] == 0 && paddr[9] == 0 && 
		paddr[10] == 0xff && paddr[11] == 0xff)
	{
		return true;
	}
	else
	{
		return false;
	}
}

const struct ppm_param_info* sinsp_utils::find_longest_matching_evt_param(string name)
{
	uint32_t maxlen = 0;
	const struct ppm_param_info* res = NULL;

	for(uint32_t j = 0; j < PPM_EVENT_MAX; j++)
	{
		const ppm_event_info* ei = &g_infotables.m_event_info[j];

		for(uint32_t k = 0; k < ei->nparams; k++)
		{
			const struct ppm_param_info* pi = &ei->params[k];
			const char* an = pi->name;
			uint32_t alen = strlen(an);
			string subs = string(name, 0, alen);
			
			if(subs == an)
			{
				if(alen > maxlen)
				{
					res = pi;
					maxlen = alen;
				}
			}
		}
	}

	return res;
}

#ifdef HAS_FILTERING
void sinsp_utils::get_filtercheck_fields_info(OUT vector<const filter_check_info*>* list)
{
	g_filterlist.get_all_fields(list);
}
#endif

///////////////////////////////////////////////////////////////////////////////
// gettimeofday() windows implementation
///////////////////////////////////////////////////////////////////////////////
#ifdef _WIN32

#include <time.h>
#include <windows.h> 

const __int64 DELTA_EPOCH_IN_MICROSECS = 11644473600000000;

int gettimeofday(struct timeval *tv, struct timezone2 *tz)
{
	FILETIME ft;
	__int64 tmpres = 0;
	TIME_ZONE_INFORMATION tz_winapi;
	int rez=0;

	ZeroMemory(&ft,sizeof(ft));
	ZeroMemory(&tz_winapi,sizeof(tz_winapi));

	GetSystemTimeAsFileTime(&ft);

	tmpres = ft.dwHighDateTime;
	tmpres <<= 32;
	tmpres |= ft.dwLowDateTime;

	//
	// converting file time to unix epoch
	//
	tmpres /= 10;  // convert into microseconds
	tmpres -= DELTA_EPOCH_IN_MICROSECS; 
	tv->tv_sec = (__int32)(tmpres*0.000001);
	tv->tv_usec =(tmpres%1000000);

	//
	// _tzset(),don't work properly, so we use GetTimeZoneInformation
	//
	if(tz)
	{
		rez=GetTimeZoneInformation(&tz_winapi);
		tz->tz_dsttime=(rez==2)?true:false;
		tz->tz_minuteswest = tz_winapi.Bias + ((rez==2)?tz_winapi.DaylightBias:0);
	}

	return 0;
}
#endif // _WIN32

///////////////////////////////////////////////////////////////////////////////
// gethostname wrapper
///////////////////////////////////////////////////////////////////////////////
string sinsp_gethostname()
{
	char hname[256];
	int res = gethostname(hname, sizeof(hname) / sizeof(hname[0]));

	if(res == 0)
	{
		return hname;
	}
	else
	{
		ASSERT(false);
		return "";
	}
}

///////////////////////////////////////////////////////////////////////////////
// tuples to string
///////////////////////////////////////////////////////////////////////////////
string ipv4tuple_to_string(ipv4tuple* tuple)
{
	char buf[50];
	sprintf(buf, 
		"%d.%d.%d.%d:%d->%d.%d.%d.%d:%d", 
		(tuple->m_fields.m_sip & 0xFF),
		((tuple->m_fields.m_sip & 0xFF00) >> 8),
		((tuple->m_fields.m_sip & 0xFF0000) >> 16),
		((tuple->m_fields.m_sip & 0xFF000000) >> 24),
		tuple->m_fields.m_sport,
		(tuple->m_fields.m_dip & 0xFF),
		((tuple->m_fields.m_dip & 0xFF00) >> 8),
		((tuple->m_fields.m_dip & 0xFF0000) >> 16),
		((tuple->m_fields.m_dip & 0xFF000000) >> 24),
		tuple->m_fields.m_dport);
	return string(buf);
}

string ipv6tuple_to_string(_ipv6tuple* tuple)
{
	char source_address[100];
	char destination_address[100];
	char buf[200];

	if(NULL == inet_ntop(AF_INET6, tuple->m_fields.m_sip, source_address, 100))
	{
		return string();
	}

	if(NULL == inet_ntop(AF_INET6, tuple->m_fields.m_dip, destination_address, 100))
	{
		return string();
	}
	
	snprintf(buf,200,"%s:%u->%s:%u",
		source_address,
		tuple->m_fields.m_sport,
		destination_address,
		tuple->m_fields.m_dport);
	
	return string(buf);
}

string ipv4serveraddr_to_string(ipv4serverinfo* addr)
{
	char buf[50];
	sprintf(buf, 
		"%d.%d.%d.%d:%d", 
		(addr->m_ip & 0xFF),
		((addr->m_ip & 0xFF00) >> 8),
		((addr->m_ip & 0xFF0000) >> 16),
		((addr->m_ip & 0xFF000000) >> 24),
		addr->m_port);
	return string(buf);
}

string ipv6serveraddr_to_string(ipv6serverinfo* addr)
{
	char address[100];
	char buf[200];

	if(NULL == inet_ntop(AF_INET6, addr->m_ip, address, 100))
	{
		return string();
	}

	snprintf(buf,200,"%s:%u",
		address,
		addr->m_port);
	
	return string(buf);
}

///////////////////////////////////////////////////////////////////////////////
// String split
///////////////////////////////////////////////////////////////////////////////
vector<string> sinsp_split(const string &s, char delim)
{
    vector<string> res;
    istringstream f(s);
    string ts;

    while(getline(f, ts, delim)) 
	{
        res.push_back(ts);
    }

	return res;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_numparser implementation
///////////////////////////////////////////////////////////////////////////////
uint32_t sinsp_numparser::parseu8(const string& str)
{
	uint32_t res;
	char temp;

	if(std::sscanf(str.c_str(), "%" PRIu8 "%c", &res, &temp) != 1)
	{
		throw sinsp_exception(str + " is not a valid number");
	}

	return res;
}

int32_t sinsp_numparser::parsed8(const string& str)
{
	int32_t res;
	char temp;

	if(std::sscanf(str.c_str(), "%" PRId8 "%c", &res, &temp) != 1)
	{
		throw sinsp_exception(str + " is not a valid number");
	}

	return res;
}

uint32_t sinsp_numparser::parseu16(const string& str)
{
	uint32_t res;
	char temp;

	if(std::sscanf(str.c_str(), "%" PRIu16 "%c", &res, &temp) != 1)
	{
		throw sinsp_exception(str + " is not a valid number");
	}

	return res;
}

int32_t sinsp_numparser::parsed16(const string& str)
{
	int32_t res;
	char temp;

	if(std::sscanf(str.c_str(), "%" PRId16 "%c", &res, &temp) != 1)
	{
		throw sinsp_exception(str + " is not a valid number");
	}

	return res;
}

uint32_t sinsp_numparser::parseu32(const string& str)
{
	uint32_t res;
	char temp;

	if(std::sscanf(str.c_str(), "%" PRIu32 "%c", &res, &temp) != 1)
	{
		throw sinsp_exception(str + " is not a valid number");
	}

	return res;
}

int32_t sinsp_numparser::parsed32(const string& str)
{
	int32_t res;
	char temp;

	if(std::sscanf(str.c_str(), "%" PRId32 "%c", &res, &temp) != 1)
	{
		throw sinsp_exception(str + " is not a valid number");
	}

	return res;
}

uint64_t sinsp_numparser::parseu64(const string& str)
{
	uint64_t res;
	char temp;

	if(std::sscanf(str.c_str(), "%" PRIu64 "%c", &res, &temp) != 1)
	{
		throw sinsp_exception(str + " is not a valid number");
	}

	return res;
}

int64_t sinsp_numparser::parsed64(const string& str)
{
	int64_t res;
	char temp;

	if(std::sscanf(str.c_str(), "%" PRId64 "%c", &res, &temp) != 1)
	{
		throw sinsp_exception(str + " is not a valid number");
	}

	return res;
}

bool sinsp_numparser::tryparseu32(const string& str, uint32_t* res)
{
	char temp;

	if(std::sscanf(str.c_str(), "%" PRIu32 "%c", res, &temp) != 1)
	{
		return false;
	}

	return true;
}

bool sinsp_numparser::tryparsed32(const string& str, int32_t* res)
{
	char temp;

	if(std::sscanf(str.c_str(), "%" PRId32 "%c", res, &temp) != 1)
	{
		return false;
	}

	return true;
}

bool sinsp_numparser::tryparseu64(const string& str, uint64_t* res)
{
	char temp;

	if(std::sscanf(str.c_str(), "%" PRIu64 "%c", res, &temp) != 1)
	{
		return false;
	}

	return true;
}

bool sinsp_numparser::tryparsed64(const string& str, int64_t* res)
{
	char temp;

	if(std::sscanf(str.c_str(), "%" PRId64 "%c", res, &temp) != 1)
	{
		return false;
	}

	return true;
}
