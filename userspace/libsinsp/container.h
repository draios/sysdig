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

#include <functional>

#if !defined(_WIN32) && !defined(CYGWING_AGENT) && defined(HAS_CAPTURE)
#include <curl/curl.h>
#include <curl/easy.h>
#include <curl/multi.h>
#endif

enum sinsp_container_type
{
	CT_DOCKER = 0,
	CT_LXC = 1,
	CT_LIBVIRT_LXC = 2,
	CT_MESOS = 3,
	CT_RKT = 4,
	CT_CUSTOM = 5
};

enum sinsp_docker_response
{
	RESP_OK = 0,
	RESP_BAD_REQUEST = 1,
	RESP_ERROR = 2
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

		std::string to_string() const
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
#ifdef HAS_ANALYZER
		,m_metadata_deadline(0)
#endif
	{
	}

	static void parse_json_mounts(const Json::Value &mnt_obj, vector<container_mount_info> &mounts);

	const vector<string>& get_env() const { return m_env; }

	const container_mount_info *mount_by_idx(uint32_t idx) const;
	const container_mount_info *mount_by_source(std::string &source) const;
	const container_mount_info *mount_by_dest(std::string &dest) const;

	string m_id;
	sinsp_container_type m_type;
	string m_name;
	string m_image;
	string m_imageid;
	string m_imagerepo;
	string m_imagetag;
	string m_imagedigest;
	uint32_t m_container_ip;
	bool m_privileged;
	vector<container_mount_info> m_mounts;
	vector<container_port_mapping> m_port_mappings;
	map<string, string> m_labels;
	vector<string> m_env;
	string m_mesos_task_id;
	int64_t m_memory_limit;
	int64_t m_swap_limit;
	int64_t m_cpu_shares;
	int64_t m_cpu_quota;
	int64_t m_cpu_period;
#ifdef HAS_ANALYZER
	string m_sysdig_agent_conf;
	uint64_t m_metadata_deadline;
#endif
};

class sinsp_container_manager;

typedef std::function<bool(sinsp_container_manager* manager, sinsp_threadinfo* tinfo, bool query_os_for_missing_info)> sinsp_container_engine;

class sinsp_container_engine_docker
{
public:
	sinsp_container_engine_docker();

	bool resolve(sinsp_container_manager* manager, sinsp_threadinfo* tinfo, bool query_os_for_missing_info);
	static void cleanup();

protected:
#if !defined(CYGWING_AGENT) && defined(HAS_CAPTURE)
	static size_t curl_write_callback(const char* ptr, size_t size, size_t nmemb, string* json);
#endif
	sinsp_docker_response get_docker(const sinsp_container_manager* manager, const string& url, string &json);
	bool parse_docker(sinsp_container_manager* manager, sinsp_container_info *container, sinsp_threadinfo* tinfo);

	string m_unix_socket_path;
	string m_api_version;
#if !defined(CYGWING_AGENT) && defined(HAS_CAPTURE)
	static CURLM *m_curlm;
	static CURL *m_curl;
#endif
};

#ifndef CYGWING_AGENT
class sinsp_container_engine_lxc
{
public:
	bool resolve(sinsp_container_manager* manager, sinsp_threadinfo* tinfo, bool query_os_for_missing_info);
};

class sinsp_container_engine_libvirt_lxc
{
public:
	bool resolve(sinsp_container_manager* manager, sinsp_threadinfo* tinfo, bool query_os_for_missing_info);
protected:
	bool match(sinsp_threadinfo* tinfo, sinsp_container_info* container_info);
};

class sinsp_container_engine_mesos
{
public:
	bool resolve(sinsp_container_manager* manager, sinsp_threadinfo* tinfo, bool query_os_for_missing_info);
	static bool set_mesos_task_id(sinsp_container_info* container, sinsp_threadinfo* tinfo);
protected:
	bool match(sinsp_threadinfo* tinfo, sinsp_container_info* container_info);
	static string get_env_mesos_task_id(sinsp_threadinfo* tinfo);
};

class sinsp_container_engine_rkt
{
public:
	bool resolve(sinsp_container_manager* manager, sinsp_threadinfo* tinfo, bool query_os_for_missing_info);
protected:
	bool match(sinsp_container_manager* manager, sinsp_threadinfo* tinfo, sinsp_container_info* container_info, string& rkt_podid, string& rkt_appname, bool query_os_for_missing_info);
	bool parse_rkt(sinsp_container_info* container, const string& podid, const string& appname);
};

#endif

class sinsp_container_manager
{
public:
	sinsp_container_manager(sinsp* inspector);
	virtual ~sinsp_container_manager();

	const unordered_map<string, sinsp_container_info>* get_containers();
	bool remove_inactive_containers();
	void add_container(const sinsp_container_info& container_info, sinsp_threadinfo *thread);
	sinsp_container_info * get_container(const string &id);
	void notify_new_container(const sinsp_container_info& container_info);
	template<typename E> bool resolve_container_impl(sinsp_threadinfo* tinfo, bool query_os_for_missing_info);
	template<typename E1, typename E2, typename... Args> bool resolve_container_impl(sinsp_threadinfo* tinfo, bool query_os_for_missing_info);
	bool resolve_container(sinsp_threadinfo* tinfo, bool query_os_for_missing_info);
	void dump_containers(scap_dumper_t* dumper);
	string get_container_name(sinsp_threadinfo* tinfo);

	bool container_exists(const string& container_id) const {
		return m_containers.find(container_id) != m_containers.end();
	}

	typedef std::function<void(const sinsp_container_info&, sinsp_threadinfo *)> new_container_cb;
	typedef std::function<void(const sinsp_container_info&)> remove_container_cb;
	void subscribe_on_new_container(new_container_cb callback);
	void subscribe_on_remove_container(remove_container_cb callback);

	void cleanup();
private:
	string container_to_json(const sinsp_container_info& container_info);
	bool container_to_sinsp_event(const string& json, sinsp_evt* evt);
	string get_docker_env(const Json::Value &env_vars, const string &mti);

	sinsp* m_inspector;
	unordered_map<string, sinsp_container_info> m_containers;
	uint64_t m_last_flush_time_ns;
	list<new_container_cb> m_new_callbacks;
	list<remove_container_cb> m_remove_callbacks;
};

template<typename E> bool sinsp_container_manager::resolve_container_impl(sinsp_threadinfo* tinfo, bool query_os_for_missing_info)
{
	E engine;
	return engine.resolve(this, tinfo, query_os_for_missing_info);
}

template<typename E1, typename E2, typename... Args> bool sinsp_container_manager::resolve_container_impl(sinsp_threadinfo* tinfo, bool query_os_for_missing_info)
{
	if (resolve_container_impl<E1>(tinfo, query_os_for_missing_info))
	{
		return true;
	}
	return resolve_container_impl<E2, Args...>(tinfo, query_os_for_missing_info);
}
