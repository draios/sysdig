#include "sinsp.h"
#include "sinsp_int.h"
#include "value_parser.h"

#ifdef _WIN32
#pragma comment(lib, "Ws2_32.lib")
#include <WinSock2.h>
#else
#include <netdb.h>
#endif

void sinsp_filter_value_parser::string_to_rawval(const char* str, uint32_t len, uint8_t *storage, string::size_type max_len, ppm_param_type ptype)
{
	switch(ptype)
	{
		case PT_INT8:
			*(int8_t*)storage = sinsp_numparser::parsed8(str);
			break;
		case PT_INT16:
			*(int16_t*)storage = sinsp_numparser::parsed16(str);
			break;
		case PT_INT32:
			*(int32_t*)storage = sinsp_numparser::parsed32(str);
			break;
		case PT_INT64:
		case PT_FD:
		case PT_ERRNO:
			*(int64_t*)storage = sinsp_numparser::parsed64(str);
			break;
		case PT_L4PROTO: // This can be resolved in the future
		case PT_FLAGS8:
		case PT_UINT8:
			*(uint8_t*)storage = sinsp_numparser::parseu8(str);
			break;
		case PT_PORT:
		{
			string in(str);

			if(in.empty())
			{
				*(uint16_t*)storage = 0;
			}
			else
			{
				// if the string is made only of numbers
				if(strspn(in.c_str(), "0123456789") == in.size())
				{
					*(uint16_t*)storage = stoi(in);
				}
				else
				{
					struct servent* se = getservbyname(in.c_str(), NULL);

					if(se == NULL)
					{
						throw sinsp_exception("unrecognized protocol " + in);
					}
					else
					{
						*(uint16_t*)storage = ntohs(getservbyname(in.c_str(), NULL)->s_port);
					}
				}
			}

			break;
		}
		case PT_FLAGS16:
		case PT_UINT16:
			*(uint16_t*)storage = sinsp_numparser::parseu16(str);
			break;
		case PT_FLAGS32:
		case PT_UINT32:
			*(uint32_t*)storage = sinsp_numparser::parseu32(str);
			break;
		case PT_UINT64:
			*(uint64_t*)storage = sinsp_numparser::parseu64(str);
			break;
		case PT_RELTIME:
		case PT_ABSTIME:
			*(uint64_t*)storage = sinsp_numparser::parseu64(str);
			break;
		case PT_CHARBUF:
		case PT_SOCKADDR:
		case PT_SOCKFAMILY:
			{
				len = (uint32_t)strlen(str);
				if(len >= max_len)
				{
					throw sinsp_exception("filter parameter too long:" + string(str));
				}

				memcpy(storage, str, len);
				*(uint8_t*)(&storage[len]) = 0;
			}
			break;
		case PT_BOOL:
			if(string(str) == "true")
			{
				*(uint32_t*)storage = 1;
			}
			else if(string(str) == "false")
			{
				*(uint32_t*)storage = 0;
			}
			else
			{
				throw sinsp_exception("filter error: unrecognized boolean value " + string(str));
			}

			break;
		case PT_IPV4ADDR:
			if(inet_pton(AF_INET, str, storage) != 1)
			{
				throw sinsp_exception("unrecognized IP address " + string(str));
			}
			break;
		case PT_IPV4NET:
		{
			stringstream ss(str);
			string ip, mask;
			ipv4net* net = (ipv4net*)storage;

			if (strchr(str, '/') == NULL)
			{
				throw sinsp_exception("unrecognized IP network " + string(str));
			}

			getline(ss, ip, '/');
			getline(ss, mask);

			if(inet_pton(AF_INET, ip.c_str(), &net->m_ip) != 1)
			{
				throw sinsp_exception("unrecognized IP address " + string(str));
			}

			uint32_t cidrlen = sinsp_numparser::parseu8(mask);

			if (cidrlen > 32)
			{
				throw sinsp_exception("invalid netmask " + mask);
			}

			uint32_t j;
			net->m_netmask = 0;

			for(j = 0; j < cidrlen; j++)
			{
				net->m_netmask |= 1<<(31-j);
			}

			net->m_netmask = htonl(net->m_netmask);

			break;
		}
		default:
			ASSERT(false);
			throw sinsp_exception("wrong parameter type " + to_string((long long) ptype));
	}
}

