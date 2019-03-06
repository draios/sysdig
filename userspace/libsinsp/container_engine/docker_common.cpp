/*
Copyright (C) 2013-2019 Draios Inc dba Sysdig.

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

#include "container_engine/docker.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "container.h"
#include "utils.h"

using namespace libsinsp::container_engine;

docker_async_source::docker_async_source(uint64_t max_wait_ms, uint64_t ttl_ms)
	: async_key_value_source(max_wait_ms, ttl_ms)
{
}

docker_async_source::~docker_async_source()
{
}

void docker_async_source::set_inspector(sinsp *inspector)
{
	m_inspector = inspector;
}

void docker_async_source::run_impl()
{
	std::string container_id;

	while (dequeue_next_key(container_id))
	{
		sinsp_container_info container;
		container.m_type = CT_DOCKER;
		container.m_id = container_id;

		if(!parse_docker(container_id, &container))
		{
			g_logger.format(sinsp_logger::SEV_DEBUG, "Failed to get Docker metadata for container %s",
					container_id.c_str());
		}

		// Return a container_info object either way, to
		// ensure any new container callbacks are called.
		store_value(container_id, container);
	}
}

void docker_async_source::set_top_tid(const std::string &container_id, sinsp_threadinfo *tinfo)
{
	top_tid_table::accessor acc;

	m_top_tids.insert(acc, container_id);
	acc->second = tinfo->m_tid;
}

int64_t docker_async_source::get_top_tid(const std::string &container_id)
{
	top_tid_table::const_accessor cacc;

	if(m_top_tids.find(cacc, container_id))
	{
		return cacc->second;
	}

	g_logger.log("Did not find container id->tid mapping for in-progress container metadata lookup?", sinsp_logger::SEV_ERROR);
	return 0;
}

bool docker_async_source::pending_lookup(std::string &container_id)
{
	top_tid_table::const_accessor cacc;

	return m_top_tids.find(cacc, container_id);
}

void docker_async_source::update_top_tid(std::string &container_id, sinsp_threadinfo *tinfo)
{
	// See if the current top tid still exists.
	top_tid_table::const_accessor cacc;
	sinsp_threadinfo *top_tinfo;

	int64_t top_tid = get_top_tid(container_id);

	if(((top_tinfo = m_inspector->get_thread(top_tid)) == NULL) ||
	   top_tinfo->m_flags & PPM_CL_CLOSED)
	{
		// The top thread no longer exists. Starting with tinfo,
		// walk the parent heirarchy to find the top thread in
		// the same container.

		sinsp_threadinfo::visitor_func_t visitor =
		[&] (sinsp_threadinfo *ptinfo)
		{
			// Stop at the first thread not in this container.
			if(ptinfo->m_container_id != container_id)
			{
				return false;
			}

			// Ignore exited threads but keep traversing.
			if(ptinfo->m_flags & PPM_CL_CLOSED)
			{
				return true;
			}

			if(ptinfo->m_container_id == container_id)
			{
				top_tinfo = ptinfo;
			}

			return true;
		};

		top_tinfo = tinfo;
		tinfo->traverse_parent_state(visitor);

		// At this point, top_tinfo should point to the top
		// thread of those running in the container.
		set_top_tid(container_id, top_tinfo);
	}
}

bool docker_async_source::m_query_image_info = true;

void docker::parse_json_mounts(const Json::Value &mnt_obj, vector<sinsp_container_info::container_mount_info> &mounts)
{
	if(!mnt_obj.isNull() && mnt_obj.isArray())
	{
		for(uint32_t i=0; i<mnt_obj.size(); i++)
		{
			const Json::Value &mount = mnt_obj[i];
			mounts.emplace_back(mount["Source"], mount["Destination"],
					    mount["Mode"], mount["RW"],
					    mount["Propagation"]);
		}
	}
}

void docker_async_source::set_query_image_info(bool query_image_info)
{
	m_query_image_info = query_image_info;
}

void docker::set_enabled(bool enabled)
{
	m_enabled = enabled;
}

bool docker::resolve(sinsp_container_manager* manager, sinsp_threadinfo* tinfo, bool query_os_for_missing_info)
{
	std::string container_id, container_name;
	sinsp_container_info *existing_container_info;

	if (!m_enabled)
	{
		return false;
	}

	if(!g_docker_info_source)
	{
		uint64_t max_wait_ms = 10000;
		docker_async_source *src = new docker_async_source(docker_async_source::NO_WAIT_LOOKUP, max_wait_ms);
		g_docker_info_source.reset(src);
		g_docker_info_source->set_inspector(manager->get_inspector());
	}

	if(!detect_docker(tinfo, container_id, container_name))
	{
		return false;
	}

	tinfo->m_container_id = container_id;

	existing_container_info = manager->get_container(container_id);

	if(!existing_container_info)
	{
		// Add a minimal container_info object where only the
		// container id, (possibly) name, and a container
		// image=incomplete is filled in. This may be
		// overidden later once parse_docker_async completes.
		sinsp_container_info container_info;

		container_info.m_type = CT_UNKNOWN;
		container_info.m_id = container_id;
		container_info.m_name = container_name;
		container_info.m_image="incomplete";
		container_info.m_metadata_complete = false;

		manager->add_container(container_info, tinfo);

		existing_container_info = manager->get_container(container_id);
	}

	// Possibly start a lookup for this container info
	if(!existing_container_info->m_metadata_complete &&
	    query_os_for_missing_info)
	{
		if(!g_docker_info_source->pending_lookup(container_id))
		{
			// give CRI a chance to return metadata for this container
			parse_docker_async(manager->get_inspector(), container_id, manager);

			g_docker_info_source->set_top_tid(container_id, tinfo);
		}
		else
		{
			g_docker_info_source->update_top_tid(container_id, tinfo);
		}
	}

	// Returning true will prevent other container engines from
	// trying to resolve the container, so only return true if we
	// have complete metadata.
	return existing_container_info->m_metadata_complete;
}

void docker::parse_docker_async(sinsp *inspector, std::string &container_id, sinsp_container_manager *manager)
{
	auto cb = [manager](const std::string &container_id, const sinsp_container_info &container_info)
        {
		int64_t top_tid = docker::g_docker_info_source->get_top_tid(container_id);
		// If here, we know it's a docker container, so set the type
		manager->notify_new_container(container_info, top_tid);
	};

        sinsp_container_info dummy;

	if (g_docker_info_source->lookup(container_id, dummy, cb))
	{
		// This should *never* happen, as ttl is 0 (never wait)
		g_logger.log("Unexpected immediate return from docker_info_source.lookup()", sinsp_logger::SEV_ERROR);
	}
}

bool docker_async_source::parse_docker(std::string &container_id, sinsp_container_info *container)
{
	string json;

	docker_response resp = get_docker(build_request("/containers/" + container_id + "/json"), json);
	switch(resp) {
		case docker_response::RESP_BAD_REQUEST:
			m_api_version = "";
			json = "";
			resp = get_docker(build_request("/containers/" + container_id + "/json"), json);
			if (resp == docker_response::RESP_OK)
			{
				break;
			}
			/* FALLTHRU */
		case docker_response::RESP_ERROR:
			return false;

		case docker_response::RESP_OK:
			break;
	}

	Json::Value root;
	Json::Reader reader;
	bool parsingSuccessful = reader.parse(json, root);
	if(!parsingSuccessful)
	{
		ASSERT(false);
		return false;
	}

	const Json::Value& config_obj = root["Config"];

	container->m_image = config_obj["Image"].asString();

	string imgstr = root["Image"].asString();
	size_t cpos = imgstr.find(":");
	if(cpos != string::npos)
	{
		container->m_imageid = imgstr.substr(cpos + 1);
	}

	container->parse_healthcheck(config_obj["Healthcheck"]);

	// Saving full healthcheck for container event parsing/writing
	container->m_healthcheck_obj = config_obj["Healthcheck"];

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
		string hostname, port;
		sinsp_utils::split_container_image(container->m_image,
						   hostname,
						   port,
						   container->m_imagerepo,
						   container->m_imagetag,
						   container->m_imagedigest,
						   false);
	}

	if(m_query_image_info && !container->m_imageid.empty() &&
	   (no_name || container->m_imagedigest.empty() || (!container->m_imagedigest.empty() && container->m_imagetag.empty())))
	{
		string img_json;
		if(get_docker(build_request("/images/" + container->m_imageid + "/json?digests=1"), img_json) == docker_response::RESP_OK)
		{
			Json::Value img_root;
			if(reader.parse(img_json, img_root))
			{
				for(const auto& rdig : img_root["RepoDigests"])
				{
					if(rdig.isString())
					{
						string repodigest = rdig.asString();
						if(container->m_imagerepo.empty())
						{
							container->m_imagerepo = repodigest.substr(0, repodigest.find("@"));
						}
						if(repodigest.find(container->m_imagerepo) != string::npos)
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
						string repotag = rtag.asString();
						if(container->m_imagerepo.empty())
						{
							container->m_imagerepo = repotag.substr(0, repotag.rfind(":"));
						}
						if(repotag.find(container->m_imagerepo) != string::npos)
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
	// k8s Docker container names could have '/' as the first character.
	if(!container->m_name.empty() && container->m_name[0] == '/')
	{
		container->m_name = container->m_name.substr(1);
	}
	if(container->m_name.find("k8s_POD") == 0)
	{
		container->m_is_pod_sandbox = true;
	}

	const Json::Value& net_obj = root["NetworkSettings"];

	string ip = net_obj["IPAddress"].asString();

	if(ip.empty())
	{
 		const Json::Value& hconfig_obj = root["HostConfig"];
		string net_mode = hconfig_obj["NetworkMode"].asString();

		if(strncmp(net_mode.c_str(), "container:", strlen("container:")) == 0)
		{
			std::string container_id = net_mode.substr(net_mode.find(":") + 1);

			sinsp_container_info pcnt;
			pcnt.m_id = container_id;

			// This is a *blocking* fetch of the
			// secondary container, but we're in a
			// separate thread so this is ok.
			parse_docker(container_id, &pcnt);
			container->m_container_ip = pcnt.m_container_ip;
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

	vector<string> ports = net_obj["Ports"].getMemberNames();
	for(vector<string>::const_iterator it = ports.begin(); it != ports.end(); ++it)
	{
		size_t tcp_pos = it->find("/tcp");
		if(tcp_pos == string::npos)
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

	vector<string> labels = config_obj["Labels"].getMemberNames();
	for(vector<string>::const_iterator it = labels.begin(); it != labels.end(); ++it)
	{
		string val = config_obj["Labels"][*it].asString();
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

	docker::parse_json_mounts(root["Mounts"], container->m_mounts);

#ifdef HAS_ANALYZER
	sinsp_utils::find_env(container->m_sysdig_agent_conf, container->get_env(), "SYSDIG_AGENT_CONF");
	// container->m_sysdig_agent_conf = get_docker_env(env_vars, "SYSDIG_AGENT_CONF");
#endif
	return true;
}
