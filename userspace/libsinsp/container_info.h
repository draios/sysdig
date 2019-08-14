/*
Copyright (C) 2013-2018 Draios Inc dba Sysdig.

This file is part of sysdig.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <list>
#include <string>
#include <vector>

#include "json/json.h"

class sinsp;
class sinsp_threadinfo;

enum sinsp_container_type
{
	CT_DOCKER = 0,
	CT_LXC = 1,
	CT_LIBVIRT_LXC = 2,
	CT_MESOS = 3,
	CT_RKT = 4,
	CT_CUSTOM = 5,
	CT_CRI = 6,
	CT_CONTAINERD = 7,
	CT_CRIO = 8,
	CT_BPM = 9,
};

class sinsp_threadinfo;

// Docker and CRI-compatible runtimes are very similar
static inline bool is_docker_compatible(sinsp_container_type t)
{
	return t == CT_DOCKER ||
		t == CT_CRI ||
		t == CT_CONTAINERD ||
		t == CT_CRIO;
}

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

		container_mount_info(const std::string&& source, const std::string&& dest,
				     const std::string&& mode, const bool rw,
				     const std::string&& propagation) :
			m_source(source), m_dest(dest), m_mode(mode), m_rdwr(rw), m_propagation(propagation)
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

	class container_health_probe
	{
	public:

		// The type of health probe
		enum probe_type {
			PT_NONE = 0,
			PT_HEALTHCHECK,
			PT_LIVENESS_PROBE,
			PT_READINESS_PROBE,
			PT_END
		};

		// String representations of the above, suitable for
		// parsing to/from json. Should be kept in sync with
		// probe_type enum.
		static std::vector<std::string> probe_type_names;

		// Parse any health probes out of the provided
		// container json, updating the list of probes.
		static void parse_health_probes(const Json::Value &config_obj,
						std::list<container_health_probe> &probes);

		// Serialize the list of health probes, adding to the provided json object
		static void add_health_probes(const std::list<container_health_probe> &probes,
					      Json::Value &config_obj);

		container_health_probe();
		container_health_probe(const probe_type probe_type,
				       const std::string &&exe,
				       const std::vector<std::string> &&args);
		virtual ~container_health_probe();

		// The probe_type that should be used for commands
		// matching this health probe.
		probe_type m_probe_type;

		// The actual health probe exe and args.
		std::string m_health_probe_exe;
		std::vector<std::string> m_health_probe_args;
	};

	sinsp_container_info():
		m_container_ip(0),
		m_privileged(false),
		m_memory_limit(0),
		m_swap_limit(0),
		m_cpu_shares(1024),
		m_cpu_quota(0),
		m_cpu_period(100000),
		m_is_pod_sandbox(false),
		m_metadata_complete(true),
		m_metadata_deadline(0)
	{
	}

	const std::vector<std::string>& get_env() const { return m_env; }

	const container_mount_info *mount_by_idx(uint32_t idx) const;
	const container_mount_info *mount_by_source(std::string &source) const;
	const container_mount_info *mount_by_dest(std::string &dest) const;

	bool is_pod_sandbox() const {
		return m_is_pod_sandbox;
	}

	std::shared_ptr<sinsp_threadinfo> get_tinfo(sinsp* inspector) const;

	// Match a process against the set of health probes
	container_health_probe::probe_type match_health_probe(sinsp_threadinfo *tinfo);

	std::string m_id;
	sinsp_container_type m_type;
	std::string m_name;
	std::string m_image;
	std::string m_imageid;
	std::string m_imagerepo;
	std::string m_imagetag;
	std::string m_imagedigest;
	uint32_t m_container_ip;
	bool m_privileged;
	std::vector<container_mount_info> m_mounts;
	std::vector<container_port_mapping> m_port_mappings;
	std::map<std::string, std::string> m_labels;
	std::vector<std::string> m_env;
	std::string m_mesos_task_id;
	int64_t m_memory_limit;
	int64_t m_swap_limit;
	int64_t m_cpu_shares;
	int64_t m_cpu_quota;
	int64_t m_cpu_period;
	std::list<container_health_probe> m_health_probes;

	bool m_is_pod_sandbox;

	// If false, this represents incomplete information about the
	// container that will be filled in later as a result of an
	// async fetch of container info.
	bool m_metadata_complete;
#ifdef HAS_ANALYZER
	std::string m_sysdig_agent_conf;
#endif
	uint64_t m_metadata_deadline;
};
