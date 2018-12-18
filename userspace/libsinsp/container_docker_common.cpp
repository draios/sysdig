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

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <grpc++/grpc++.h>
#include "cri.pb.h"
#include "cri.grpc.pb.h"

#define CONTAINER_CPP
typedef runtime::v1alpha2::RuntimeService::Stub RuntimeService_Stub;
#endif

#include "container_docker_common.h"
#include "container_mesos.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "container.h"
#include "utils.h"
#ifdef CYGWING_AGENT
#include "dragent_win_hal_public.h"
#endif


#if !defined(CYGWING_AGENT) && defined(HAS_CAPTURE)
CURLM *sinsp_container_engine_docker::m_curlm = NULL;
CURL *sinsp_container_engine_docker::m_curl = NULL;
unique_ptr<runtime::v1alpha2::RuntimeService::Stub> sinsp_container_engine_docker::m_containerd = nullptr;
#endif

bool sinsp_container_engine_docker::m_query_image_info = true;

#if !defined(CYGWING_AGENT) && defined(HAS_CAPTURE)
sinsp_container_engine_docker::sinsp_container_engine_docker() :
	m_unix_socket_path(string(scap_get_host_root()) + "/var/run/docker.sock"),
	m_containerd_unix_socket_path("unix://" + string(scap_get_host_root()) + "/run/containerd/containerd.sock"),
	m_api_version("/v1.24")
{
	if(!m_curlm)
	{
		m_curl = curl_easy_init();
		m_curlm = curl_multi_init();

		if(m_curlm)
		{
			curl_multi_setopt(m_curlm, CURLMOPT_PIPELINING, CURLPIPE_HTTP1|CURLPIPE_MULTIPLEX);
		}

		if(m_curl)
		{
			curl_easy_setopt(m_curl, CURLOPT_UNIX_SOCKET_PATH, m_unix_socket_path.c_str());
			curl_easy_setopt(m_curl, CURLOPT_HTTPGET, 1);
			curl_easy_setopt(m_curl, CURLOPT_FOLLOWLOCATION, 1);
			curl_easy_setopt(m_curl, CURLOPT_WRITEFUNCTION, curl_write_callback);
		}
	}

	if(!m_containerd)
	{
		m_containerd = runtime::v1alpha2::RuntimeService::NewStub(
			grpc::CreateChannel(m_containerd_unix_socket_path, grpc::InsecureChannelCredentials()));
	}
}
#else
sinsp_container_engine_docker::sinsp_container_engine_docker() :
	m_api_version("/v1.30")
{
}
#endif

void sinsp_container_engine_docker::cleanup()
{
#if !defined(CYGWING_AGENT) && defined(HAS_CAPTURE)
	curl_easy_cleanup(m_curl);
	m_curl = NULL;
	curl_multi_cleanup(m_curlm);
	m_curlm = NULL;

	m_containerd.reset(nullptr);
#endif
}

void sinsp_container_engine_docker::parse_json_mounts(const Json::Value &mnt_obj, vector<sinsp_container_info::container_mount_info> &mounts)
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

void sinsp_container_engine_docker::set_query_image_info(bool query_image_info)
{
	m_query_image_info = query_image_info;
}

#if !defined(CYGWING_AGENT) && defined(HAS_CAPTURE)
size_t sinsp_container_engine_docker::curl_write_callback(const char* ptr, size_t size, size_t nmemb, string* json)
{
	const std::size_t total = size * nmemb;
	json->append(ptr, total);
	return total;
}
#endif

std::string sinsp_container_engine_docker::build_request(const std::string &url)
{
#ifndef CYGWING_AGENT
	return "http://localhost" + m_api_version + url;
#else
	return "GET " + m_api_version + url + " HTTP/1.1\r\nHost: docker\r\n\r\n";
#endif
}

bool sinsp_container_engine_docker::parse_docker(sinsp_container_manager* manager, sinsp_container_info *container, sinsp_threadinfo* tinfo)
{
	string json;
	sinsp_docker_response resp = get_docker(manager, build_request("/containers/" + container->m_id + "/json"), json);
	switch(resp) {
		case sinsp_docker_response::RESP_BAD_REQUEST:
			m_api_version = "";
			json = "";
			resp = get_docker(manager, build_request("/containers/" + container->m_id + "/json"), json);
			if (resp == sinsp_docker_response::RESP_OK)
			{
				break;
			}
			/* FALLTHRU */
		case sinsp_docker_response::RESP_ERROR:
			return false;

		case sinsp_docker_response::RESP_OK:
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
		if(get_docker(manager, build_request("/images/" + container->m_imageid + "/json?digests=1"), img_json) == sinsp_docker_response::RESP_OK)
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

	if(!container->m_name.empty() && container->m_name[0] == '/')
	{
		container->m_name = container->m_name.substr(1);
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
			uint32_t container_ip;
			const sinsp_container_info *container_info = manager->get_container(container_id);
			if(container_info)
			{
				container_ip = container_info->m_container_ip;
			}
			else
			{
				sinsp_container_info pcnt;
				pcnt.m_id = container_id;
				parse_docker(manager, &pcnt, tinfo);
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

	parse_json_mounts(root["Mounts"], container->m_mounts);

#ifdef HAS_ANALYZER
	sinsp_utils::find_env(container->m_sysdig_agent_conf, container->get_env(), "SYSDIG_AGENT_CONF");
	// container->m_sysdig_agent_conf = get_docker_env(env_vars, "SYSDIG_AGENT_CONF");
#endif
	return true;
}


bool sinsp_container_engine_docker::parse_containerd(sinsp_container_manager* manager, sinsp_container_info *container, sinsp_threadinfo* tinfo)
{
#ifdef CYGWING_AGENT
	ASSERT(false);
	return false;
#else
	runtime::v1alpha2::ContainerStatusRequest req;
	runtime::v1alpha2::ContainerStatusResponse resp;
	req.set_container_id(container->m_id);
	req.set_verbose(true);
	grpc::ClientContext context;
	// XXX async
	grpc::Status status = m_containerd->ContainerStatus(&context, req, &resp);
	if (!status.ok()) {
		return false;
	}

	if (!resp.has_status())
	{
		ASSERT(false);
		return false;
	}

	const auto& resp_container = resp.status();
	container->m_name = resp_container.metadata().name();

	// image_ref may be one of two forms:
	// host/image@sha256:digest
	// sha256:digest
	const auto& image_ref = resp_container.image_ref();
	auto digest_start = image_ref.find("sha256:");
	if (digest_start != string::npos)
	{
		container->m_imagedigest = image_ref.substr(digest_start);
	}

	string hostname, port, digest;
	sinsp_utils::split_container_image(resp_container.image().image(),
					   hostname,
					   port,
					   container->m_imagerepo,
					   container->m_imagetag,
					   digest,
					   false);

	for (const auto& mount : resp_container.mounts())
	{
		const char* propagation;
		switch(mount.propagation()) {
			case runtime::v1alpha2::MountPropagation::PROPAGATION_PRIVATE:
				propagation = "private";
				break;
			case runtime::v1alpha2::MountPropagation::PROPAGATION_HOST_TO_CONTAINER:
				propagation = "rslave";
				break;
			case runtime::v1alpha2::MountPropagation::PROPAGATION_BIDIRECTIONAL:
				propagation = "rshared";
				break;
			default:
				propagation = "unknown";
				break;
		}
		container->m_mounts.emplace_back(
			mount.host_path(),
			mount.container_path(),
			"",
			!mount.readonly(),
			propagation);
	}

	for (const auto& pair : resp_container.labels())
	{
		container->m_labels[pair.first] = pair.second;
	}

	const auto& info_it = resp.info().find("info");
	if (info_it == resp.info().end())
	{
		ASSERT(false);
		return false;
	}
	Json::Value root;
	Json::Reader reader;
	bool parsingSuccessful = reader.parse(info_it->second, root);
	if(!parsingSuccessful)
	{
		ASSERT(false);
		return false;
	}

	const Json::Value& config = root["config"];
	const Json::Value& envs = config["envs"];

	for (const auto& env_var : envs)
	{
		auto key = env_var["key"].asString();
		auto value = env_var["value"].asString();
		container->m_env.emplace_back(key + '=' + value);
	}

	const Json::Value& resources = root["runtimeSpec"]["linux"]["resources"];
	container->m_memory_limit = resources["memory"]["limit"].asInt64();
	container->m_swap_limit = container->m_memory_limit;

	const Json::Value& cpu = resources["cpu"];
	container->m_cpu_shares = cpu["shares"].asInt64();
	container->m_cpu_quota = cpu["quota"].asInt64();
	container->m_cpu_period = cpu["period"].asInt64();

	const Json::Value& privileged = root["runtimeSpec"]["linux"]["security_context"]["privileged"];
	container->m_privileged = privileged.asBool();

	const auto pod_sandbox_id = root["sandboxID"].asString();
	runtime::v1alpha2::PodSandboxStatusRequest psreq;
	runtime::v1alpha2::PodSandboxStatusResponse psresp;
	psreq.set_pod_sandbox_id(pod_sandbox_id);
	psreq.set_verbose(true);
	grpc::ClientContext pscontext;
	// XXX async
	status = m_containerd->PodSandboxStatus(&pscontext, psreq, &psresp);
	if (!status.ok()) {
		return false;
	}

	const auto& pod_ip = psresp.status().network().ip();
	if (!pod_ip.empty())
	{
		long ip;
		if (inet_pton(AF_INET, pod_ip.c_str(), &ip) == -1)
		{
			ASSERT(false);
		}
		else
		{
			container->m_container_ip = ntohl(ip);
		}
	}

	return true;
#endif
}



#ifdef CYGWING_AGENT
bool sinsp_container_engine_docker::resolve(sinsp_container_manager* manager, sinsp_threadinfo* tinfo, bool query_os_for_missing_info)
{
	wh_docker_container_info wcinfo = wh_docker_resolve_pid(manager->get_inspector()->get_wmi_handle(), tinfo->m_pid);
	if(!wcinfo.m_res)
	{
		return false;
	}

	sinsp_container_info container_info;
	container_info.m_type = CT_DOCKER;
	container_info.m_id = wcinfo.m_container_id;
	container_info.m_name = wcinfo.m_container_name;

	tinfo->m_container_id = container_info.m_id;
	if (!manager->container_exists(container_info.m_id))
	{
		if (query_os_for_missing_info)
		{
			parse_docker(manager, &container_info, tinfo);
		}
		manager->add_container(container_info, tinfo);
		manager->notify_new_container(container_info);
	}
	return true;
}

sinsp_docker_response sinsp_container_engine_docker::get_docker(sinsp_container_manager* manager, const string& url, string &json)
{
	const char* response = NULL;
	bool qdres = wh_query_docker(manager->get_inspector()->get_wmi_handle(),
		(char*)url.c_str(),
		&response);
	if(qdres == false)
	{
		ASSERT(false);
		return sinsp_docker_response::RESP_ERROR;
	}

	json = response;
	if(strncmp(json.c_str(), "HTTP/1.0 200 OK", sizeof("HTTP/1.0 200 OK") -1))
	{
		return sinsp_docker_response::RESP_BAD_REQUEST;
	}

	size_t pos = json.find("{");
	if(pos == string::npos)
	{
		ASSERT(false);
		return sinsp_docker_response::RESP_ERROR;
	}
	json = json.substr(pos);

	return sinsp_docker_response::RESP_OK;
}

#else
bool sinsp_container_engine_docker::resolve(sinsp_container_manager* manager, sinsp_threadinfo* tinfo, bool query_os_for_missing_info)
{
	sinsp_container_info container_info;
	bool matches = false;

	for(auto it = tinfo->m_cgroups.begin(); it != tinfo->m_cgroups.end(); ++it)
	{
		string cgroup = it->second;
		size_t pos;

		//
		// Non-systemd Docker
		//
		pos = cgroup.find_last_of("/");
		if(pos != string::npos)
		{
			if(cgroup.length() - pos - 1 == 64 &&
			   cgroup.find_first_not_of("0123456789abcdefABCDEF", pos + 1) == string::npos)
			{
				container_info.m_type = CT_DOCKER;
				container_info.m_id = cgroup.substr(pos + 1, 12);
				matches = true;
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
				matches = true;
				break;
			}
		}
	}

	if (!matches)
		return false;

	tinfo->m_container_id = container_info.m_id;
	if (!manager->container_exists(container_info.m_id))
	{
#ifndef _WIN32
		if (query_os_for_missing_info)
		{
			if (!parse_docker(manager, &container_info, tinfo))
			{
				parse_containerd(manager, &container_info, tinfo);
			}
			if (sinsp_container_engine_mesos::set_mesos_task_id(&container_info, tinfo))
			{
				g_logger.format(sinsp_logger::SEV_DEBUG,
					"Mesos Docker container: [%s], Mesos task ID: [%s]",
					container_info.m_id.c_str(), container_info.m_mesos_task_id.c_str());
			}
		}
#endif
		manager->add_container(container_info, tinfo);
		manager->notify_new_container(container_info);
	}
	return true;
}

sinsp_docker_response sinsp_container_engine_docker::get_docker(sinsp_container_manager* manager, const string& url, string &json)
{
#ifdef HAS_CAPTURE
	if(curl_easy_setopt(m_curl, CURLOPT_URL, url.c_str()) != CURLE_OK)
	{
		ASSERT(false);
		return sinsp_docker_response::RESP_ERROR;
	}
	if(curl_easy_setopt(m_curl, CURLOPT_WRITEDATA, &json) != CURLE_OK)
	{
		ASSERT(false);
		return sinsp_docker_response::RESP_ERROR;
	}

	if(curl_multi_add_handle(m_curlm, m_curl) != CURLM_OK)
	{
		ASSERT(false);
		return sinsp_docker_response::RESP_ERROR;
	}

	while(true)
	{
		int still_running;
		CURLMcode res = curl_multi_perform(m_curlm, &still_running);
		if(res != CURLM_OK)
		{
			ASSERT(false);
			return sinsp_docker_response::RESP_ERROR;
		}

		if(still_running == 0)
		{
			break;
		}

		int numfds;
		res = curl_multi_wait(m_curlm, NULL, 0, -1, &numfds);
		if(res != CURLM_OK)
		{
			ASSERT(false);
			return sinsp_docker_response::RESP_ERROR;
		}
	}

	if(curl_multi_remove_handle(m_curlm, m_curl) != CURLM_OK)
	{
		ASSERT(false);
		return sinsp_docker_response::RESP_ERROR;
	}

	long http_code = 0;
	if(curl_easy_getinfo(m_curl, CURLINFO_RESPONSE_CODE, &http_code) != CURLE_OK)
	{
		ASSERT(false);
		return sinsp_docker_response::RESP_ERROR;
	}
	switch(http_code)
	{
		case 0: /* connection failed, apparently */
			return sinsp_docker_response::RESP_ERROR;
		case 200:
			return sinsp_docker_response::RESP_OK;
		default:
			return sinsp_docker_response::RESP_BAD_REQUEST;
	}

	return sinsp_docker_response::RESP_OK;
#else
	return sinsp_docker_response::RESP_ERROR;
#endif
}

#endif
