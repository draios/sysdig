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

enum sinsp_container_type
{
	CT_DOCKER = 0,
	CT_LXC = 1,
	CT_LIBVIRT_LXC = 2,
	CT_MESOS = 3
};

class sinsp_container_info
{
public:
	class container_port_mapping
	{
	public:
		container_port_mapping():
			m_host_ip(0),
			m_host_port(0),
			m_container_port(0)
		{
		}

		uint32_t m_host_ip;
		uint16_t m_host_port;
		uint16_t m_container_port;
	};

	sinsp_container_info():
		m_container_ip(0)
	{
	}

	string m_id;
	sinsp_container_type m_type;
	string m_name;
	string m_image;
	uint32_t m_container_ip;
	vector<container_port_mapping> m_port_mappings;
	map<string, string> m_labels;
};

class sinsp_container_manager
{
public:
	sinsp_container_manager(sinsp* inspector);

	const unordered_map<string, sinsp_container_info>* get_containers();
	bool remove_inactive_containers();
	void add_container(const sinsp_container_info& container_info);
	bool get_container(const string& id, sinsp_container_info* container_info);
	bool resolve_container_from_cgroups(const vector<pair<string, string>>& cgroups, bool query_os_for_missing_info, string* container_id);
	void dump_containers(scap_dumper_t* dumper);
	string get_container_name(sinsp_threadinfo* tinfo);

private:
	bool container_to_sinsp_event(const sinsp_container_info& container_info, sinsp_evt* evt, size_t evt_len);
	bool parse_docker(sinsp_container_info* container);

	sinsp* m_inspector;
	unordered_map<string, sinsp_container_info> m_containers;
	uint64_t m_last_flush_time_ns;
};
