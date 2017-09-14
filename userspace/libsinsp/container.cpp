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
#include "utils.h"

void sinsp_container_info::parse_json_mounts(const Json::Value &mnt_obj, vector<sinsp_container_info::container_mount_info> &mounts)
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

sinsp_container_info::container_mount_info *sinsp_container_info::mount_by_idx(uint32_t idx)
{
	if (idx >= m_mounts.size())
	{
		return NULL;
	}

	return &(m_mounts[idx]);
}

sinsp_container_info::container_mount_info *sinsp_container_info::mount_by_source(std::string &source)
{
	// note: linear search
	for (auto &mntinfo :m_mounts)
	{
		if(sinsp_utils::glob_match(source.c_str(), mntinfo.m_source.c_str()))
		{
			return &mntinfo;
		}
	}

	return NULL;
}

sinsp_container_info::container_mount_info *sinsp_container_info::mount_by_dest(std::string &dest)
{
	// note: linear search
	for (auto &mntinfo :m_mounts)
	{
		if(sinsp_utils::glob_match(dest.c_str(), mntinfo.m_dest.c_str()))
		{
			return &mntinfo;
		}
	}

	return NULL;
}

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
				if(m_inspector->m_parser->m_fd_listener)
				{
					m_inspector->m_parser->m_fd_listener->on_remove_container(m_containers[it->first]);
				}
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

bool sinsp_container_manager::get_container(const string& container_id, sinsp_container_info* container_info) const
{
	unordered_map<string, sinsp_container_info>::const_iterator it = m_containers.find(container_id);
	if(it != m_containers.end())
	{
		*container_info = it->second;
		return true;
	}

	return false;
}

sinsp_container_info* sinsp_container_manager::get_container(const string& container_id)
{
	unordered_map<string, sinsp_container_info>::iterator it = m_containers.find(container_id);
	if(it != m_containers.end())
	{
		return &it->second;
	}

	return NULL;
}

string sinsp_container_manager::get_env_mesos_task_id(sinsp_threadinfo* tinfo)
{
	string mtid;

	sinsp_threadinfo::visitor_func_t visitor = [&mtid] (sinsp_threadinfo *ptinfo)
	{
		// Mesos task ID detection is not a straightforward task;
		// this list may have to be extended.
		mtid = ptinfo->get_env("MESOS_TASK_ID"); // Marathon
		if(!mtid.empty()) { return false; }
		mtid = ptinfo->get_env("mesos_task_id"); // Chronos
		if(!mtid.empty()) { return false; }
		mtid = ptinfo->get_env("MESOS_EXECUTOR_ID"); // others
		if(!mtid.empty()) { return false; }

		return true;
	};

	// Try the current thread first. visitor returns true if mtid
	// was not filled in. In this case we should traverse the
	// parents.
	if(tinfo && visitor(tinfo))
	{
		tinfo->traverse_parent_state(visitor);
	}

	return mtid;
}

bool sinsp_container_manager::set_mesos_task_id(sinsp_container_info* container, sinsp_threadinfo* tinfo)
{
	ASSERT(container);
	ASSERT(tinfo);

	// there are applications that do not share their environment in /proc/[PID]/environ
	// since we need MESOS_TASK_ID environment variable to discover Mesos containers,
	// there is a workaround for such cases:
	// - for docker containers, we discover it directly from container, through Remote API
	//   (see sinsp_container_manager::parse_docker() for details)
	// - for mesos native containers, parent process has the MESOS_TASK_ID (or equivalent, see
	//   get_env_mesos_task_id(sinsp_threadinfo*) implementation) environment variable, so we
	//   peek into the parent process environment to discover it

	if(container && tinfo)
	{
		string& mtid = container->m_mesos_task_id;
		if(mtid.empty())
		{
			mtid = get_env_mesos_task_id(tinfo);
			if(!mtid.empty())
			{
				g_logger.log("Mesos native container: [" + container->m_id + "], Mesos task ID: " + mtid, sinsp_logger::SEV_DEBUG);
				return true;
			}
			else
			{
				g_logger.log("Mesos task ID not found for Mesos container [" + container->m_id + "],"
							 "thread [" + std::to_string(tinfo->m_tid) + ']', sinsp_logger::SEV_DEBUG);
			}
		}
	}
	return false;
}

string sinsp_container_manager::get_mesos_task_id(const string& container_id)
{
	string mesos_task_id;
	const sinsp_container_info* container = get_container(container_id);
	if(container)
	{
		mesos_task_id = container->m_mesos_task_id;
	}
	return mesos_task_id;
}

bool sinsp_container_manager::resolve_container(sinsp_threadinfo* tinfo, bool query_os_for_missing_info)
{

	ASSERT(tinfo);
	bool valid_id = false;
	sinsp_container_info container_info;

	string rkt_podid, rkt_appname;
	// Start with cgroup based detection
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
				break;
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
				break;
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
				break;
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
			break;
		}

		//
		// Non-systemd LXC
		//
		pos = cgroup.find("/lxc/");
		if(pos != string::npos)
		{
			auto id_start = pos + sizeof("/lxc/") - 1;
			auto id_end = cgroup.find('/', id_start);
			container_info.m_type = CT_LXC;
			container_info.m_id = cgroup.substr(id_start, id_end - id_start);
			valid_id = true;
			break;
		}

		//
		// Mesos
		//
		pos = cgroup.find("/mesos/");
		if(pos != string::npos)
		{
			container_info.m_type = CT_MESOS;
			container_info.m_id = cgroup.substr(pos + sizeof("/mesos/") - 1);
			// Consider a mesos container valid only if we find the mesos_task_id
			// this will exclude from the container itself the mesos-executor
			// but makes sure that we have task_id parsed properly. Otherwise what happens
			// is that we'll create a mesos container struct without a mesos_task_id
			// and for all other processes we'll use it
			valid_id = set_mesos_task_id(&container_info, tinfo);
			break;
		}

		//
		// systemd rkt
		//
		// rkt cgroups
		// 1. /system.slice/k8s_d1efb75a-ad42-458e-af65-2b378f42173f.service/system.slice/redis.service
		// 2. /machine.slice/machine-rkt\x2dc508ad4c\x2d7fa4\x2d4513\x2d9d53\x2d007628003805.scope/system.slice/redis.service
		static const string COREOS_PODID_VAR = "container_uuid=";
		static const string SYSTEMD_UUID_ARG = "--uuid=";
		static const string SERVICE_SUFFIX = ".service";
		if(cgroup.rfind(SERVICE_SUFFIX) == cgroup.size() - SERVICE_SUFFIX.size())
		{
			// check if there is a parent with pod uuid var
			sinsp_threadinfo::visitor_func_t visitor = [&rkt_podid](sinsp_threadinfo* ptinfo)
			{
				for(const auto& env_var : ptinfo->get_env())
				{
					auto container_uuid_pos = env_var.find(COREOS_PODID_VAR);
					if(container_uuid_pos == 0)
					{
						rkt_podid = env_var.substr(COREOS_PODID_VAR.size());
						return false;
					}
				}
				for(const auto& arg : ptinfo->m_args)
				{
					if(arg.find(SYSTEMD_UUID_ARG) != string::npos)
					{
						rkt_podid = arg.substr(SYSTEMD_UUID_ARG.size());
						return false;
					}
				}
				return true;
			};
			tinfo->traverse_parent_state(visitor);

			if(!rkt_podid.empty())
			{
				auto last_slash = cgroup.find_last_of("/");
				rkt_appname = cgroup.substr(last_slash + 1, cgroup.size() - last_slash - SERVICE_SUFFIX.size() - 1);
				
				char image_manifest_path[SCAP_MAX_PATH_SIZE];
				snprintf(image_manifest_path, sizeof(image_manifest_path), "%s/var/lib/rkt/pods/run/%s/appsinfo/%s/manifest", scap_get_host_root(), rkt_podid.c_str(), rkt_appname.c_str());

				// First lookup if the container exists in our table, otherwise only if we are live check if it has
				// an entry in /var/lib/rkt. In capture mode only the former will be used.
				// In live mode former will be used only if we already hit that container
				bool is_rkt_pod_id_valid = m_containers.find(rkt_podid + ":" + rkt_appname) != m_containers.end(); // if it's already on our table
#ifdef HAS_CAPTURE
				if(!is_rkt_pod_id_valid && query_os_for_missing_info)
				{
					is_rkt_pod_id_valid = (access(image_manifest_path, F_OK) == 0);
				}
#endif			
				if(is_rkt_pod_id_valid)
				{
					container_info.m_type = CT_RKT;
					container_info.m_id = rkt_podid + ":" + rkt_appname;
					container_info.m_name = rkt_appname;
					valid_id = true;
					break;
				}
			}
		}
	}

	// If anything has been found, try proc root based detection
	// right now used for rkt
	if(!valid_id)
	{
		// Try parsing from process root,
		// Strings used to detect rkt stage1-cores pods
		// TODO: detecting stage1-coreos rkt pods in this way is deprecated
		// we can remove it in the future
		static const string COREOS_PREFIX = "/opt/stage2/";
		static const string COREOS_APP_SUFFIX = "/rootfs";
		static const string COREOS_PODID_VAR = "container_uuid=";

		auto prefix = tinfo->m_root.find(COREOS_PREFIX);
		if(prefix == 0)
		{
			auto suffix = tinfo->m_root.find(COREOS_APP_SUFFIX, prefix);
			if(suffix != string::npos)
			{
				rkt_appname = tinfo->m_root.substr(prefix + COREOS_PREFIX.size(), suffix - prefix - COREOS_PREFIX.size());
				// It is a rkt pod with stage1-coreos

				sinsp_threadinfo::visitor_func_t visitor = [&rkt_podid, &container_info, &rkt_appname, &valid_id] (sinsp_threadinfo *ptinfo)
				{
					for(const auto& env_var : ptinfo->get_env())
					{
						auto container_uuid_pos = env_var.find(COREOS_PODID_VAR);
						if(container_uuid_pos == 0)
						{
							rkt_podid = env_var.substr(COREOS_PODID_VAR.size());
							container_info.m_type = CT_RKT;
							container_info.m_id = rkt_podid + ":" + rkt_appname;
							container_info.m_name = rkt_appname;
							valid_id = true;
							return false;
						}
					}
					return true;
				};

				// Try the current thread first. visitor returns true if no coreos pid
				// info was found. In this case we traverse the parents.
				if (visitor(tinfo))
				{
					tinfo->traverse_parent_state(visitor);
				}
			}
		}
		else
		{
			// String used to detect stage1-fly pods
			static const string FLY_PREFIX = "/var/lib/rkt/pods/run/";
			static const string FLY_PODID_SUFFIX = "/stage1/rootfs/opt/stage2/";
			static const string FLY_APP_SUFFIX = "/rootfs";

			auto prefix = tinfo->m_root.find(FLY_PREFIX);
			if(prefix == 0)
			{
				auto podid_suffix = tinfo->m_root.find(FLY_PODID_SUFFIX, prefix+FLY_PREFIX.size());
				if(podid_suffix != string::npos)
				{
					rkt_podid = tinfo->m_root.substr(prefix + FLY_PREFIX.size(), podid_suffix - prefix - FLY_PREFIX.size());
					auto appname_suffix = tinfo->m_root.find(FLY_APP_SUFFIX, podid_suffix+FLY_PODID_SUFFIX.size());
					if(appname_suffix != string::npos)
					{
						rkt_appname = tinfo->m_root.substr(podid_suffix + FLY_PODID_SUFFIX.size(),
														   appname_suffix-podid_suffix-FLY_PODID_SUFFIX.size());
						container_info.m_type = CT_RKT;
						container_info.m_id = rkt_podid + ":" + rkt_appname;
						container_info.m_name = rkt_appname;
						valid_id = true;
					}
				}
			}
		}
	}

	if(!valid_id) {
		tinfo->m_container_id = "";
	}
	else
	{
		tinfo->m_container_id = container_info.m_id;

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
				case CT_MESOS:
					container_info.m_name = container_info.m_id;
					break;
				case CT_RKT:
#ifndef _WIN32
					if(query_os_for_missing_info)
					{
						parse_rkt(&container_info, rkt_podid, rkt_appname);
					}
#endif
					break;
				default:
					ASSERT(false);
			}

			add_container(container_info);
			if(container_to_sinsp_event(container_to_json(container_info), &m_inspector->m_meta_evt))
			{
				m_inspector->m_meta_evt_pending = true;
			}
		}
	}

	return valid_id;
}

string sinsp_container_manager::container_to_json(const sinsp_container_info& container_info)
{
	Json::Value obj;
	Json::Value& container = obj["container"];
	container["id"] = container_info.m_id;
	container["type"] = container_info.m_type;
	container["name"] = container_info.m_name;
	container["image"] = container_info.m_image;
	container["imageid"] = container_info.m_imageid;
	container["privileged"] = container_info.m_privileged;

	Json::Value mounts = Json::arrayValue;

	for (auto &mntinfo : container_info.m_mounts)
	{
		Json::Value mount;

		mount["Source"] = mntinfo.m_source;
		mount["Destination"] = mntinfo.m_dest;
		mount["Mode"] = mntinfo.m_mode;
		mount["RW"] = mntinfo.m_rdwr;
		mount["Propagation"] = mntinfo.m_propagation;

		mounts.append(mount);
	}

	container["Mounts"] = mounts;

	char addrbuff[100];
	uint32_t iph = htonl(container_info.m_container_ip);
	inet_ntop(AF_INET, &iph, addrbuff, sizeof(addrbuff));
	container["ip"] = addrbuff;

	if(!container_info.m_mesos_task_id.empty())
	{
		container["mesos_task_id"] = container_info.m_mesos_task_id;
	}
	return Json::FastWriter().write(obj);
}

bool sinsp_container_manager::container_to_sinsp_event(const string& json, sinsp_evt* evt)
{
	// TODO: variable event length
	size_t evt_len = SP_EVT_BUF_SIZE;
	size_t totlen = sizeof(scap_evt) +  sizeof(uint16_t) + json.length() + 1;

	if(totlen > evt_len)
	{
		ASSERT(false);
		return false;
	}

	evt->m_cpuid = 0;
	evt->m_evtnum = 0;
	evt->m_inspector = m_inspector;

	scap_evt* scapevt = evt->m_pevt;

	scapevt->ts = m_inspector->m_lastevent_ts;
	scapevt->tid = 0;
	scapevt->len = (uint32_t)totlen;
	scapevt->type = PPME_CONTAINER_JSON_E;

	uint16_t* lens = (uint16_t*)((char *)scapevt + sizeof(struct ppm_evt_hdr));
	char* valptr = (char*)lens + sizeof(uint16_t);

	*lens = (uint16_t)json.length() + 1;
	memcpy(valptr, json.c_str(), *lens);

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
	while((res = read(sock, buf, sizeof(buf) - 1)) != 0)
	{
		if(res == -1 || json.size() > MAX_JSON_SIZE_B)
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

	const Json::Value& config_obj = root["Config"];

	container->m_image = config_obj["Image"].asString();

	string imgstr = root["Image"].asString();
	size_t cpos = imgstr.find(":");
	if(cpos != string::npos)
	{
		container->m_imageid = imgstr.substr(cpos + 1);
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
			sinsp_container_info pcnt;
			pcnt.m_id = net_mode.substr(net_mode.find(":") + 1);
			if(!get_container(pcnt.m_id, &pcnt))
			{
				parse_docker(&pcnt);
			}
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
	string mesos_task_id = get_docker_env(env_vars, "MESOS_TASK_ID");
	if(mesos_task_id.empty())
	{
		mesos_task_id = get_docker_env(env_vars, "mesos_task_id");
	}
	if(mesos_task_id.empty())
	{
		mesos_task_id = get_docker_env(env_vars, "MESOS_EXECUTOR_ID");
	}
	if(!mesos_task_id.empty())
	{
		container->m_mesos_task_id = mesos_task_id;
		g_logger.log("Mesos Docker container: [" + root["Id"].asString() + "], Mesos task ID: [" + container->m_mesos_task_id + ']', sinsp_logger::SEV_DEBUG);
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

	sinsp_container_info::parse_json_mounts(root["Mounts"], container->m_mounts);

#ifdef HAS_ANALYZER
	container->m_sysdig_agent_conf = get_docker_env(env_vars, "SYSDIG_AGENT_CONF");
#endif
	return true;
}

string sinsp_container_manager::get_docker_env(const Json::Value &env_vars, const string &mti)
{
	string ret;
	for(const auto& env_var : env_vars)
	{
		if(env_var.isString())
		{
			ret = env_var.asString();
			if((ret.length() > (mti.length() + 1)) && (ret.substr(0, mti.length()) == mti))
			{
				return ret.substr(mti.length() + 1);
			}
		}
	}
	return "";
}

bool sinsp_container_manager::parse_rkt(sinsp_container_info *container, const string &podid, const string &appname)
{
	bool ret = false;
	Json::Reader reader;
	Json::Value jroot;

	char image_manifest_path[SCAP_MAX_PATH_SIZE];
	snprintf(image_manifest_path, sizeof(image_manifest_path), "%s/var/lib/rkt/pods/run/%s/appsinfo/%s/manifest", scap_get_host_root(), podid.c_str(), appname.c_str());
	ifstream image_manifest(image_manifest_path);
	if(reader.parse(image_manifest, jroot))
	{
		container->m_image = jroot["name"].asString();
		for(const auto& label_entry : jroot["labels"])
		{
			container->m_labels.emplace(label_entry["name"].asString(), label_entry["value"].asString());
		}
		auto version_label_it = container->m_labels.find("version");
		if(version_label_it != container->m_labels.end())
		{
			container->m_image += ":" + version_label_it->second;
		}
		ret = true;
	}

	char net_info_path[SCAP_MAX_PATH_SIZE];
	snprintf(net_info_path, sizeof(net_info_path), "%s/var/lib/rkt/pods/run/%s/net-info.json", scap_get_host_root(), podid.c_str());
	ifstream net_info(net_info_path);
	if(reader.parse(net_info, jroot) && jroot.size() > 0)
	{
		const auto& first_net = jroot[0];
		if(inet_pton(AF_INET, first_net["ip"].asCString(), &container->m_container_ip) == -1)
		{
			ASSERT(false);
		}
		container->m_container_ip = ntohl(container->m_container_ip);
	}

	char pod_manifest_path[SCAP_MAX_PATH_SIZE];
	snprintf(pod_manifest_path, sizeof(pod_manifest_path), "%s/var/lib/rkt/pods/run/%s/pod", scap_get_host_root(), podid.c_str());
	ifstream pod_manifest(pod_manifest_path);
	unordered_map<string, uint32_t> image_ports;
	if(reader.parse(pod_manifest, jroot) && jroot.size() > 0)
	{
		for(const auto& japp : jroot["apps"])
		{
			if (japp["name"].asString() == appname)
			{
				for(const auto& image_port : japp["app"]["ports"])
				{
					image_ports[image_port["name"].asString()] = image_port["port"].asUInt();
				}
				break;
			}
		}
		for(const auto& jport : jroot["ports"])
		{
			auto host_port = jport["hostPort"].asUInt();
			auto container_port_it = image_ports.find(jport["name"].asString());
			if(host_port > 0 && container_port_it != image_ports.end())
			{
				sinsp_container_info::container_port_mapping port_mapping;
				port_mapping.m_host_port = host_port;
				port_mapping.m_container_port = container_port_it->second;
				container->m_port_mappings.emplace_back(move(port_mapping));
			}
		}
	}
	return ret;
}
#endif

const unordered_map<string, sinsp_container_info>* sinsp_container_manager::get_containers()
{
	return &m_containers;
}

void sinsp_container_manager::add_container(const sinsp_container_info& container_info)
{
	m_containers[container_info.m_id] = container_info;

	if(m_inspector->m_parser->m_fd_listener)
	{
		m_inspector->m_parser->m_fd_listener->on_new_container(container_info);
	}
}

void sinsp_container_manager::dump_containers(scap_dumper_t* dumper)
{
	for(unordered_map<string, sinsp_container_info>::const_iterator it = m_containers.begin(); it != m_containers.end(); ++it)
	{
		if(container_to_sinsp_event(container_to_json(it->second), &m_inspector->m_meta_evt))
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
