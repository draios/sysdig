/*
Copyright (C) 2018 Sysdig, Inc.

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
#include "async_docker_metadata_source.h"

#if defined(CYGWING_AGENT)
#    include "async_windows_docker_metadata_source.h"
#else
#    include "async_linux_docker_metadata_source.h"
#endif

#include "sinsp_int.h"
#include "logger.h"

using namespace sysdig;

const uint16_t async_docker_metadata_source::DEFAULT_PORT = 80;

async_docker_metadata_source::async_docker_metadata_source(const std::string& api_version,
                                           const uint16_t port):
	async_metadata_source<std::string, docker_metadata>(NO_LOOKUP_WAIT),
	m_query_image_info(true),
	m_api_version(api_version),
	m_port(port)
{
}

const std::string& async_docker_metadata_source::get_api_version() const
{
	return m_api_version;
}

uint16_t async_docker_metadata_source::get_port() const
{
	return m_port;
}

bool async_docker_metadata_source::query_image_info() const
{
	return m_query_image_info;
}

void async_docker_metadata_source::set_query_image_info(const bool query_info)
{
	m_query_image_info = query_info;
}

void async_docker_metadata_source::run_impl()
{
	while(queue_size() > 0)
	{
		const std::string container_id = dequeue_next_key();
		docker_metadata metadata = get_metadata(container_id);

		if(metadata.m_manager != nullptr)
		{
			if(parse_docker(metadata.m_manager,
					metadata.m_container_info.get()))
			{
				store_metadata(container_id, metadata);
			}
		}
		else
		{
			g_logger.log("Unexpected null manager",
			             sinsp_logger::SEV_ERROR);
			ASSERT(metadata.m_manager != nullptr);
		}
	}
}

bool async_docker_metadata_source::parse_docker(sinsp_container_manager* const manager,
                                               sinsp_container_info* const container)
{
	std::string json;
	sinsp_docker_response resp =
		get_docker(manager,
		           build_request("/containers/" + container->m_id + "/json"),
			   json);

	switch(resp)
	{
	case sinsp_docker_response::RESP_OK:
		break;

	case sinsp_docker_response::RESP_BAD_REQUEST:
		m_api_version = "";
		json = "";

		resp = get_docker(manager,
		                  build_request("/containers/" + container->m_id + "/json"),
				  json);
		if(resp == sinsp_docker_response::RESP_OK)
		{
			break;
		}
		/* FALLTHRU */

	case sinsp_docker_response::RESP_ERROR:
		ASSERT(false);
		return false;
	}

	Json::Value root;
	Json::Reader reader;
	const bool parsingSuccessful = reader.parse(json, root);
	if(!parsingSuccessful)
	{
		g_logger.log("Parsing unsuccessful", sinsp_logger::SEV_ERROR);
		ASSERT(false);
		return false;
	}

	const Json::Value& config_obj = root["Config"];

	container->m_image = config_obj["Image"].asString();

	std::string imgstr = root["Image"].asString();
	size_t cpos = imgstr.find(":");
	if(cpos != std::string::npos)
	{
		container->m_imageid = imgstr.substr(cpos + 1);
	}

	// containers can be spawned using just the imageID as image name,
	// with or without the hash prefix (e.g. sha256:)
	bool no_name = !container->m_imageid.empty() &&
		strncmp(container->m_image.c_str(), container->m_imageid.c_str(),
			MIN(container->m_image.length(), container->m_imageid.length())) == 0;
	no_name |= !imgstr.empty() &&
		strncmp(container->m_image.c_str(), imgstr.c_str(),
			MIN(container->m_image.length(), imgstr.length())) == 0;

	if(!no_name || !m_query_image_info)
	{
		std::string hostname;
		std::string port;

		sinsp_utils::split_container_image(container->m_image,
						   hostname,
						   port,
						   container->m_imagerepo,
						   container->m_imagetag,
						   container->m_imagedigest,
						   false);
	}

	if(m_query_image_info && !container->m_imageid.empty() &&
	   (no_name || container->m_imagedigest.empty() ||
	    (!container->m_imagedigest.empty() && container->m_imagetag.empty())))
	{
		std::string img_json;

		resp = get_docker(manager,
		                  build_request("/images/" + container->m_imageid + "/json?digests=1"),
				  json);
		if(resp == sinsp_docker_response::RESP_OK)
		{
			Json::Value img_root;
			if(reader.parse(img_json, img_root))
			{
				for(const auto& rdig : img_root["RepoDigests"])
				{
					if(rdig.isString())
					{
						std::string repodigest = rdig.asString();
						if(container->m_imagerepo.empty())
						{
							container->m_imagerepo = repodigest.substr(0, repodigest.find("@"));
						}
						if(repodigest.find(container->m_imagerepo) != std::string::npos)
						{
							container->m_imagedigest = repodigest.substr(repodigest.find("@")+1);
							break;
						}
					}
				}
				for(const auto& rtag : img_root["RepoTags"])
				{
					if(rtag.isString())
					{
						std::string repotag = rtag.asString();
						if(container->m_imagerepo.empty())
						{
							container->m_imagerepo = repotag.substr(0, repotag.rfind(":"));
						}
						if(repotag.find(container->m_imagerepo) != std::string::npos)
						{
							container->m_imagetag = repotag.substr(repotag.rfind(":")+1);
							break;
						}
					}
				}
			}
		}
	}
	if(container->m_imagetag.empty())
	{
		container->m_imagetag = "latest";
	}

	container->m_name = root["Name"].asString();

	if(!container->m_name.empty() && container->m_name[0] == '/')
	{
		container->m_name = container->m_name.substr(1);
	}

	const Json::Value& net_obj = root["NetworkSettings"];

	std::string ip = net_obj["IPAddress"].asString();
	if(ip.empty())
	{
		const Json::Value& hconfig_obj = root["HostConfig"];
		std::string net_mode = hconfig_obj["NetworkMode"].asString();
		if(strncmp(net_mode.c_str(), "container:", strlen("container:")) == 0)
		{
			std::string container_id = net_mode.substr(net_mode.find(":") + 1);
			uint32_t container_ip;
			const sinsp_container_info* const container_info = manager->get_container(container_id);
			if(container_info)
			{
				container_ip = container_info->m_container_ip;
			}
			else
			{
				sinsp_container_info pcnt;
				pcnt.m_id = container_id;
				parse_docker(manager, &pcnt);
				container_ip = pcnt.m_container_ip;
			}
			container->m_container_ip = container_ip;
		}
	}
	else
	{
		if(inet_pton(AF_INET, ip.c_str(), &container->m_container_ip) == -1)
		{
			ASSERT(false);
		}
		container->m_container_ip = ntohl(container->m_container_ip);
	}

	std::vector<std::string> ports = net_obj["Ports"].getMemberNames();
	for(std::vector<std::string>::const_iterator it = ports.begin(); it != ports.end(); ++it)
	{
		size_t tcp_pos = it->find("/tcp");
		if(tcp_pos == std::string::npos)
		{
			continue;
		}

		uint16_t container_port = atoi(it->c_str());

		const Json::Value& v = net_obj["Ports"][*it];
		if(v.isArray())
		{
			for(uint32_t j = 0; j < v.size(); ++j)
			{
				sinsp_container_info::container_port_mapping port_mapping;

				ip = v[j]["HostIp"].asString();
				std::string port = v[j]["HostPort"].asString();

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

	std::vector<std::string> labels = config_obj["Labels"].getMemberNames();
	for(std::vector<std::string>::const_iterator it = labels.begin(); it != labels.end(); ++it)
	{
		std::string val = config_obj["Labels"][*it].asString();
		container->m_labels[*it] = val;
	}

	const Json::Value& env_vars = config_obj["Env"];

	for(const auto& env_var : env_vars)
	{
		if(env_var.isString())
		{
			container->m_env.emplace_back(env_var.asString());
		}
	}

// TODO: Need to factor this out and get rid of the CYGWING_AGENT check
#ifndef CYGWING_AGENT
	// FIXME: Should we move this outside somewhere?
	//if (sinsp_container_engine_mesos::set_mesos_task_id(container, tinfo))
	//{
	//	g_logger.log("Mesos Docker container: [" + root["Id"].asString() + "], Mesos task ID: [" + container->m_mesos_task_id + ']', sinsp_logger::SEV_DEBUG);
	//}
#endif

	const auto& host_config_obj = root["HostConfig"];
	container->m_memory_limit = host_config_obj["Memory"].asInt64();
	container->m_swap_limit = host_config_obj["MemorySwap"].asInt64();
	const auto cpu_shares = host_config_obj["CpuShares"].asInt64();
	if(cpu_shares > 0)
	{
		container->m_cpu_shares = cpu_shares;
	}
	container->m_cpu_quota = host_config_obj["CpuQuota"].asInt64();
	const auto cpu_period = host_config_obj["CpuPeriod"].asInt64();
	if(cpu_period > 0)
	{
		container->m_cpu_period = cpu_period;
	}
	const Json::Value &privileged = host_config_obj["Privileged"];
	if(!privileged.isNull() && privileged.isBool())
	{
		container->m_privileged = privileged.asBool();
	}

	sinsp_container_info::parse_json_mounts(root["Mounts"], container->m_mounts);

#ifdef HAS_ANALYZER
	sinsp_utils::find_env(container->m_sysdig_agent_conf, container->get_env(), "SYSDIG_AGENT_CONF");
	// container->m_sysdig_agent_conf = get_docker_env(env_vars, "SYSDIG_AGENT_CONF");
#endif
	g_logger.log("EXIT: parse_docker");
	return true;
}

async_docker_metadata_source* async_docker_metadata_source::new_async_docker_metadata_source()
{
	async_docker_metadata_source* docker_metadata = nullptr;

#if defined(CYGWING_AGENT)
	docker_metadata = new async_windows_docker_metadata_source();
#else // !CYGWING_AGENT
#       if defined(HAS_CAPTURE)
		docker_metadata = new async_linux_docker_metadata_source();
#       else // !HAS_CAPTURE
		// TODO: Need to implement async_null_docker_metadata_source
		// docker_metadata = new async_null_docker_metadata_source();
#       endif //HAS_CAPTURE
#endif // CYGWING_AGENT

	return docker_metadata;
}
