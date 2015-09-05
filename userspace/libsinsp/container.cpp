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

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

#include "sinsp.h"
#include "sinsp_int.h"
#include "container.h"

sinsp_container_manager::sinsp_container_manager(sinsp* inspector) :
	m_inspector(inspector),
	m_last_flush_time_ns(0)
{
}

bool sinsp_container_manager::remove_inactive_containers()
{
	bool res = false;

	if(m_last_flush_time_ns == 0)
	{
		m_last_flush_time_ns = m_inspector->m_lastevent_ts - m_inspector->m_inactive_container_scan_time_ns + 30 * ONE_SECOND_IN_NS;
	}

	if(m_inspector->m_lastevent_ts > 
		m_last_flush_time_ns + m_inspector->m_inactive_thread_scan_time_ns)
	{
		res = true;

		m_last_flush_time_ns = m_inspector->m_lastevent_ts;

		g_logger.format(sinsp_logger::SEV_INFO, "Flushing container table");

		set<string> containers_in_use;

		threadinfo_map_t* threadtable = m_inspector->m_thread_manager->get_threads();

		for(threadinfo_map_iterator_t it = threadtable->begin(); it != threadtable->end(); ++it)
		{
			if(!it->second.m_container_id.empty())
			{
				containers_in_use.insert(it->second.m_container_id);
			}
		}

		for(unordered_map<string, sinsp_container_info>::iterator it = m_containers.begin(); it != m_containers.end();)
		{
			if(containers_in_use.find(it->first) == containers_in_use.end())
			{
				m_containers.erase(it++);
			}
			else
			{
				++it;
			}
		}
	}

	return res;
}

bool sinsp_container_manager::get_container(const string& id, sinsp_container_info* container_info)
{
	unordered_map<string, sinsp_container_info>::const_iterator it = m_containers.find(id);
	if(it != m_containers.end())
	{
		*container_info = it->second;
		return true;
	}

	return false;
}

bool sinsp_container_manager::resolve_container_from_cgroups(const vector<pair<string, string>>& cgroups, bool query_os_for_missing_info, string* container_id)
{
	bool valid_id = false;
	sinsp_container_info container_info;

	for(vector<pair<string, string>>::const_iterator it = cgroups.begin(); it != cgroups.end(); ++it)
	{
		string cgroup = it->second;
		size_t pos;

		//
		// Non-systemd Docker
		//
		pos = cgroup.find("/docker/");
		if(pos != string::npos)
		{
			if(cgroup.length() - pos - sizeof("/docker/") + 1 == 64)
			{
				container_info.m_type = CT_DOCKER;
				container_info.m_id = cgroup.substr(pos + sizeof("/docker/") - 1, 12);
				valid_id = true;
				break;
			}
		}

		//
		// systemd Docker
		//
		pos = cgroup.find("docker-");
		if(pos != string::npos)
		{
			size_t pos2 = cgroup.find(".scope");
			if(pos2 != string::npos &&
				pos2 - pos - sizeof("docker-") + 1 == 64)
			{
				container_info.m_type = CT_DOCKER;
				container_info.m_id = cgroup.substr(pos + sizeof("docker-") - 1, 12);
				valid_id = true;
				continue;
			}
		}

		//
		// Non-systemd libvirt-lxc
		//
		pos = cgroup.find(".libvirt-lxc");
		if(pos != string::npos &&
			pos == cgroup.length() - sizeof(".libvirt-lxc") + 1)
		{
			size_t pos2 = cgroup.find_last_of("/");
			if(pos2 != string::npos)
			{
				container_info.m_type = CT_LIBVIRT_LXC;
				container_info.m_id = cgroup.substr(pos2 + 1, pos - pos2 - 1);
				valid_id = true;
				continue;
			}
		}

		//
		// systemd libvirt-lxc
		//
		pos = cgroup.find("-lxc\\x2");
		if(pos != string::npos)
		{
			size_t pos2 = cgroup.find(".scope");
			if(pos2 != string::npos &&
				pos2 == cgroup.length() - sizeof(".scope") + 1)
			{
				container_info.m_type = CT_LIBVIRT_LXC;
				container_info.m_id = cgroup.substr(pos + sizeof("-lxc\\x2"), pos2 - pos - sizeof("-lxc\\x2"));
				valid_id = true;
				continue;
			}
		}

		//
		// Legacy libvirt-lxc
		//
		pos = cgroup.find("/libvirt/lxc/");
		if(pos != string::npos)
		{
			container_info.m_type = CT_LIBVIRT_LXC;
			container_info.m_id = cgroup.substr(pos + sizeof("/libvirt/lxc/") - 1);
			valid_id = true;
			continue;
		}

		//
		// Non-systemd LXC
		//
		pos = cgroup.find("/lxc/");
		if(pos != string::npos)
		{
			container_info.m_type = CT_LXC;
			container_info.m_id = cgroup.substr(pos + sizeof("/lxc/") - 1);
			valid_id = true;
			continue;
		}
	}

	if(valid_id)
	{
		*container_id = container_info.m_id;

		unordered_map<string, sinsp_container_info>::const_iterator it = m_containers.find(container_info.m_id);
		if(it == m_containers.end())
		{
			switch(container_info.m_type)
			{
				case CT_DOCKER:
#ifndef _WIN32
					if(query_os_for_missing_info)
					{
						parse_docker(&container_info);
					}
#endif
					break;
				case CT_LXC:
					container_info.m_name = container_info.m_id;
					break;
				case CT_LIBVIRT_LXC:
					container_info.m_name = container_info.m_id;
					break;
				default:
					ASSERT(false);
			}

			m_containers.insert(std::make_pair(container_info.m_id, container_info));
			if(container_to_sinsp_event(container_info, &m_inspector->m_meta_evt, SP_EVT_BUF_SIZE))
			{
				m_inspector->m_meta_evt_pending = true;
			}
		}
	}

	return valid_id;
}

bool sinsp_container_manager::container_to_sinsp_event(const sinsp_container_info& container_info, sinsp_evt* evt, size_t evt_len)
{
	size_t totlen = sizeof(scap_evt) + 
		4 * sizeof(uint16_t) +
		container_info.m_id.length() + 1 +
		sizeof(uint32_t) +
		container_info.m_name.length() + 1 +
		container_info.m_image.length() + 1;

	if(totlen > evt_len)
	{
		ASSERT(false);
		return false;
	}

	evt->m_cpuid = 0;
	evt->m_evtnum = 0;

	scap_evt* scapevt = evt->m_pevt;

	scapevt->ts = m_inspector->m_lastevent_ts;
	scapevt->tid = 0;
	scapevt->len = (uint32_t)totlen;
	scapevt->type = PPME_CONTAINER_E;

	uint16_t* lens = (uint16_t*)((char *)scapevt + sizeof(struct ppm_evt_hdr));
	char* valptr = (char*)lens + 4 * sizeof(uint16_t);

	lens[0] = (uint16_t)container_info.m_id.length() + 1;
	memcpy(valptr, container_info.m_id.c_str(), lens[0]);
	valptr += lens[0];

	lens[1] = sizeof(uint32_t);
	memcpy(valptr, &container_info.m_type, lens[1]);
	valptr += lens[1];

	lens[2] = (uint16_t)container_info.m_name.length() + 1;
	memcpy(valptr, container_info.m_name.c_str(), lens[2]);
	valptr += lens[2];

	lens[3] = (uint16_t)container_info.m_image.length() + 1;
	memcpy(valptr, container_info.m_image.c_str(), lens[3]);
	valptr += lens[3];

	evt->init();
	return true;
}

#ifndef _WIN32
bool sinsp_container_manager::parse_docker(sinsp_container_info* container)
{
	string file = string(scap_get_host_root()) + "/var/run/docker.sock";

	int sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if(sock < 0)
	{
		ASSERT(false);
		return false;
	}

	struct sockaddr_un address;
	memset(&address, 0, sizeof(struct sockaddr_un));

	address.sun_family = AF_UNIX;
	strncpy(address.sun_path, file.c_str(), sizeof(address.sun_path) - 1);
	address.sun_path[sizeof(address.sun_path) - 1]= '\0';

	if(connect(sock, (struct sockaddr *) &address, sizeof(struct sockaddr_un)) != 0)
	{
		return false;
	}

	string message = "GET /containers/" + container->m_id + "/json HTTP/1.0\r\n\n";
	if(write(sock, message.c_str(), message.length()) != (ssize_t) message.length())
	{
		ASSERT(false);
		close(sock);
		return false;
	}

	char buf[256];
	string json;
	ssize_t res;
	while((res = read(sock, buf, sizeof(buf))) != 0)
	{
		if(res == -1)
		{
			ASSERT(false);
			close(sock);
			return false;
		}

		buf[res] = 0;
		json += buf;
	}

	close(sock);

	size_t pos = json.find("{");
	if(pos == string::npos)
	{
		ASSERT(false);
		return false;
	}

	Json::Value root;
	Json::Reader reader;
	bool parsingSuccessful = reader.parse(json.substr(pos), root);
	if(!parsingSuccessful)
	{
		ASSERT(false);
		return false;
	}

	container->m_image = root["Config"]["Image"].asString();
	container->m_name = root["Name"].asString();
	if(!container->m_name.empty() && container->m_name[0] == '/')
	{
		container->m_name = container->m_name.substr(1);
	}

	string ip = root["NetworkSettings"]["IPAddress"].asString();
	if(inet_pton(AF_INET, ip.c_str(), &container->m_container_ip) == -1)
	{
		ASSERT(false);
	}
	container->m_container_ip = ntohl(container->m_container_ip);

	vector<string> ports = root["NetworkSettings"]["Ports"].getMemberNames();
	for(vector<string>::const_iterator it = ports.begin(); it != ports.end(); ++it)
	{
		size_t tcp_pos = it->find("/tcp");
		if(tcp_pos == string::npos)
		{
			continue;
		}

		uint16_t container_port = atoi(it->c_str());

		Json::Value& v = root["NetworkSettings"]["Ports"][*it];
		if(v.isArray())
		{
			for(uint32_t j = 0; j < v.size(); ++j)
			{	
				sinsp_container_info::container_port_mapping port_mapping;

				ip = v[j]["HostIp"].asString();
				string port = v[j]["HostPort"].asString();

				if(inet_pton(AF_INET, ip.c_str(), &port_mapping.m_host_ip) == -1)
				{
					ASSERT(false);
					continue;
				}
				port_mapping.m_host_ip = ntohl(port_mapping.m_host_ip);

				port_mapping.m_container_port = container_port;
				port_mapping.m_host_port = atoi(port.c_str());
				container->m_port_mappings.push_back(port_mapping);
			}
		}
	}

	vector<string> labels = root["Config"]["Labels"].getMemberNames();
	for(vector<string>::const_iterator it = labels.begin(); it != labels.end(); ++it)
	{
		string val = root["Config"]["Labels"][*it].asString();
		container->m_labels[*it] = val;
	}
	
	return true;
}
#endif

const unordered_map<string, sinsp_container_info>* sinsp_container_manager::get_containers()
{
	return &m_containers;
}

void sinsp_container_manager::add_container(const sinsp_container_info& container_info)
{
	m_containers[container_info.m_id] = container_info;
}

void sinsp_container_manager::dump_containers(scap_dumper_t* dumper)
{
	for(unordered_map<string, sinsp_container_info>::const_iterator it = m_containers.begin(); it != m_containers.end(); ++it)
	{
		if(container_to_sinsp_event(it->second, &m_inspector->m_meta_evt, SP_EVT_BUF_SIZE))
		{
			int32_t res = scap_dump(m_inspector->m_h, dumper, m_inspector->m_meta_evt.m_pevt, m_inspector->m_meta_evt.m_cpuid, 0);
			if(res != SCAP_SUCCESS)
			{
				throw sinsp_exception(scap_getlasterr(m_inspector->m_h));
			}
		}
	}
}

string sinsp_container_manager::get_container_name(sinsp_threadinfo* tinfo)
{
	string res;

	if(tinfo->m_container_id.empty())
	{
		res = "host";
	}
	else
	{
		sinsp_container_info container_info;
		bool found = get_container(tinfo->m_container_id, &container_info);
		if(!found)
		{
			return NULL;
		}

		if(container_info.m_name.empty())
		{
			return NULL;
		}

		res = container_info.m_name;
	}

	return res;
}
