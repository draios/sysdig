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

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

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
			if(!it->second.m_container.m_id.empty())
			{
				containers_in_use.insert(it->second.m_container.m_id);
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

bool sinsp_container_manager::get_container_from_cgroups(const vector<pair<string, string>>& cgroups, sinsp_container_info* container_info)
{
	bool valid_id = false;

	for(vector<pair<string, string>>::const_iterator it = cgroups.begin(); it != cgroups.end(); ++it)
	{
		string cgroup = it->second;
		size_t pos;

		//
		// Plain docker
		//
		pos = cgroup.find("/docker/");
		if(pos != string::npos)
		{
			if(cgroup.length() - pos - sizeof("/docker/") + 1 == 64)
			{
				container_info->m_type = CT_DOCKER;
				container_info->m_id = cgroup.substr(pos + sizeof("/docker/") - 1, 12);
				valid_id = true;
				break;
			}
		}

		//
		// Docker sliced with systemd on EL7
		//
		pos = cgroup.find("docker-");
		if(pos != string::npos)
		{
			size_t pos2 = cgroup.find(".scope");
			if(pos2 != string::npos &&
				pos2 - pos - sizeof("docker-") + 1 == 64)
			{
				container_info->m_type = CT_DOCKER;
				container_info->m_id = cgroup.substr(pos + sizeof("docker-") - 1, 12);
				valid_id = true;
				continue;					
			}
		}

		//
		// Plain LXC
		//
		pos = cgroup.find("/lxc/");
		if(pos != string::npos)
		{
			container_info->m_type = CT_LXC;
			container_info->m_id = cgroup.substr(pos + sizeof("/lxc/") - 1);
			valid_id = true;
			continue;
		}
	}

	if(valid_id)
	{
		unordered_map<string, sinsp_container_info>::const_iterator it = m_containers.find(container_info->m_id);
		if(it == m_containers.end())
		{
			switch(container_info->m_type)
			{
				case CT_DOCKER:
					parse_docker(container_info);
					break;
				case CT_LXC:
					container_info->m_name = container_info->m_id;
					break;
				default:
					ASSERT(false);
			}

			m_containers.insert(std::make_pair(container_info->m_id, *container_info));
		}
		else
		{
			*container_info = it->second;
		}
	}

	return valid_id;
}

void sinsp_container_manager::parse_docker(sinsp_container_info* container)
{
	string file = string(scap_get_host_root()) + "/var/run/docker.sock";

	int sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if(sock < 0)
	{
		ASSERT(false);
		return;
	}

	struct sockaddr_un address;
	memset(&address, 0, sizeof(struct sockaddr_un));

	address.sun_family = AF_UNIX;
	snprintf(address.sun_path, sizeof(address.sun_path), file.c_str());

	if(connect(sock, (struct sockaddr *) &address, sizeof(struct sockaddr_un)) != 0)
	{
		return;
	}

	string message = "GET /containers/" + container->m_id + "/json HTTP/1.0\r\n\n";
	if(write(sock, message.c_str(), message.length()) != (ssize_t) message.length())
	{
		ASSERT(false);
		close(sock);
		return;
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
			return;
		}

		buf[res] = 0;
		json += buf;
	}

	close(sock);

	size_t pos = json.find("{");
	if(pos == string::npos)
	{
		ASSERT(false);
		return;
	}

	Json::Value root;
	Json::Reader reader;
	bool parsingSuccessful = reader.parse(json.substr(pos), root);
	if(!parsingSuccessful)
	{
		ASSERT(false);
		return;
	}

	if(root.isMember("Config") && root["Config"].isMember("Image"))
	{
		container->m_image = root["Config"]["Image"].asString();
	}

	if(root.isMember("Name"))
	{
		container->m_name = root["Name"].asString().substr(1);
	}
}
