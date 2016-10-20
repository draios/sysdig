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
	CT_MESOS = 3,
	CT_RKT = 4
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

	class container_mount_info
	{
	public:
         	container_mount_info():
         		m_source(""),
			m_dest(""),
			m_mode(""),
			m_rdwr(false),
			m_propagation("")
		{
		}

		container_mount_info(const Json::Value &source, const Json::Value &dest,
				     const Json::Value &mode, const Json::Value &rw,
				     const Json::Value &propagation)
		{
			get_string_value(source, m_source);
			get_string_value(dest, m_dest);
			get_string_value(mode, m_mode);
			get_string_value(propagation, m_propagation);

			if(!rw.isNull() && rw.isBool())
			{
				m_rdwr = rw.asBool();
			}
		}

		std::string to_string()
		{
			return m_source + ":" +
				m_dest + ":" +
				m_mode + ":" +
				(m_rdwr ? "true" : "false") + ":" +
				m_propagation;
		}

		inline void get_string_value(const Json::Value &val, std::string &result)
		{
			if(!val.isNull() && val.isString())
			{
				result = val.asString();
			}
		}

		std::string m_source;
		std::string m_dest;
		std::string m_mode;
		bool m_rdwr;
		std::string m_propagation;
	};

	sinsp_container_info():
		m_container_ip(0),
		m_privileged(false),
		m_memory_limit(0),
		m_swap_limit(0),
		m_cpu_shares(1024),
		m_cpu_quota(0),
		m_cpu_period(100000)
	{
	}

	static void parse_json_mounts(const Json::Value &mnt_obj, vector<container_mount_info> &mounts);

	container_mount_info *mount_by_idx(uint32_t idx);
	container_mount_info *mount_by_source(std::string &source);
	container_mount_info *mount_by_dest(std::string &dest);

	string m_id;
	sinsp_container_type m_type;
	string m_name;
	string m_image;
	string m_imageid;
	uint32_t m_container_ip;
	bool m_privileged;
	vector<container_mount_info> m_mounts;
	vector<container_port_mapping> m_port_mappings;
	map<string, string> m_labels;
	string m_mesos_task_id;
	int64_t m_memory_limit;
	int64_t m_swap_limit;
	int64_t m_cpu_shares;
	int64_t m_cpu_quota;
	int64_t m_cpu_period;
};

class sinsp_container_manager
{
public:
	sinsp_container_manager(sinsp* inspector);

	const unordered_map<string, sinsp_container_info>* get_containers();
	bool remove_inactive_containers();
	void add_container(const sinsp_container_info& container_info);
	bool get_container(const string& id, sinsp_container_info* container_info) const;
	bool resolve_container(sinsp_threadinfo* tinfo, bool query_os_for_missing_info);
	void dump_containers(scap_dumper_t* dumper);
	string get_container_name(sinsp_threadinfo* tinfo);
	string get_env_mesos_task_id(sinsp_threadinfo* tinfo);
	bool set_mesos_task_id(sinsp_container_info* container, sinsp_threadinfo* tinfo);
	string get_mesos_task_id(const string& container_id);

private:
	string container_to_json(const sinsp_container_info& container_info);
	bool container_to_sinsp_event(const string& json, sinsp_evt* evt);
	bool parse_docker(sinsp_container_info* container);
	string get_mesos_task_id(const Json::Value& env_vars, const string& mti);
	bool parse_rkt(sinsp_container_info* container, const string& podid, const string& appname);
	sinsp_container_info* get_container(const string& id);

	sinsp* m_inspector;
	unordered_map<string, sinsp_container_info> m_containers;
	uint64_t m_last_flush_time_ns;
};
