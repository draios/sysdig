//
// k8s_component.cpp
//

#include "k8s_component.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include <sstream>
#include <iostream>

//
// container
//

k8s_container::k8s_container()
{
}

k8s_container::k8s_container(const std::string& name, const port_list& ports): m_name(name),
		m_ports(ports)
{
}

k8s_container::k8s_container(const k8s_container& other): m_name(other.m_name),
	m_ports(other.m_ports)
{
}

k8s_container::k8s_container(k8s_container&& other): m_name(std::move(other.m_name)),
	m_ports(std::move(other.m_ports))
{
}

k8s_container& k8s_container::operator=(const k8s_container& other)
{
	m_name = other.m_name;
	m_ports = other.m_ports;
	return *this;
}

bool k8s_container::has_port(const std::string& port_name) const
{
	for(const auto& port : m_ports)
	{
		if (port.get_name() == port_name)
		{
			return true;
		}
	}
	return false;
}

const k8s_container::port* k8s_container::get_port(const std::string& port_name) const
{
	for(const auto& port : m_ports)
	{
		if (port.get_name() == port_name)
		{
			return &port;
		}
	}
	return 0;
}

//
// component
//

const k8s_component::component_map k8s_component::list =
{
	{ k8s_component::K8S_NODES,                  "nodes"                  },
	{ k8s_component::K8S_NAMESPACES,             "namespaces"             },
	{ k8s_component::K8S_PODS,                   "pods"                   },
	{ k8s_component::K8S_REPLICATIONCONTROLLERS, "replicationcontrollers" },
	{ k8s_component::K8S_SERVICES,               "services"               }
};

k8s_component::k8s_component(const std::string& name, const std::string& uid, const std::string& ns) : 
	m_name(name), m_uid(uid), m_ns(ns)
{
}

k8s_pair_list k8s_component::extract_object(const Json::Value& object, const std::string& name)
{
	k8s_pair_list entry_list;
	if(!object.isNull())
	{
		Json::Value entries = object[name];
		if(!entries.isNull())
		{
			Json::Value::Members members = entries.getMemberNames();
			for (auto& member : members)
			{
				Json::Value val = entries[member];
				if(!val.isNull())
				{
					entry_list.emplace_back(k8s_pair_t(member, val.asString()));
				}
			}
		}
	}
	return entry_list;
}

std::vector<std::string> k8s_component::extract_pod_container_ids(const Json::Value& item)
{
	std::vector<std::string> container_list;
	Json::Value status = item["status"];
	if(!status.isNull())
	{
		Json::Value containers = status["containerStatuses"];
		if(!containers.isNull())
		{
			for (auto& container : containers)
			{
				Json::Value container_id = container["containerID"];
				if(!container_id.isNull())
				{
					container_list.emplace_back(container_id.asString());
				}
			}
		}
	}
	return container_list;
}

size_t k8s_component::extract_pod_restart_count(const Json::Value& item)
{
	size_t restart_count = 0;
	Json::Value status = item["status"];
	if(!status.isNull())
	{
		Json::Value containers = status["containerStatuses"];
		if(!containers.isNull())
		{
			for (auto& container : containers)
			{
				Json::Value rc = container["restartCount"];
				if(!rc.isNull() && rc.isInt())
				{
					restart_count += rc.asInt();
				}
			}
		}
	}
	return restart_count;
}

k8s_container::list k8s_component::extract_pod_containers(const Json::Value& item)
{
	k8s_container::list ext_containers;
	Json::Value spec = item["spec"];
	if(!spec.isNull())
	{
		Json::Value containers = spec["containers"];
		if(!containers.isNull())
		{
			for (auto& container : containers)
			{
				std::string cont_name;
				Json::Value name = container["name"];
				if(!name.isNull()) { cont_name = name.asString(); }
				else { return ext_containers; }

				k8s_container::port_list cont_ports;
				Json::Value ports = container["ports"];
				for(const auto& port : ports)
				{
					k8s_container::port cont_port;
					Json::Value name = port["name"];
					if(!name.isNull())
					{
						cont_port.set_name(name.asString());
					}
					Json::Value cport = port["containerPort"];
					if(!cport.isNull())
					{
						cont_port.set_port(cport.asUInt());
					}
					else
					{
						g_logger.log("Port not found, setting value to 0", sinsp_logger::SEV_WARNING);
						cont_port.set_port(0);
					}
					Json::Value protocol = port["protocol"];
					if(!protocol.isNull())
					{
						cont_port.set_protocol(protocol.asString());
					}
					else
					{
						std::string port_name = name.isNull() ? "[NO NAME]" : name.asString();
						g_logger.log("Protocol not found for port: " + port_name, sinsp_logger::SEV_WARNING);
					}
					cont_ports.push_back(cont_port);
				}
				ext_containers.emplace_back(k8s_container(cont_name, cont_ports));
			}
		}
	}
	return ext_containers;
}

void k8s_component::extract_pod_data(const Json::Value& item, k8s_pod_t& pod)
{
	Json::Value spec = item["spec"];
	if(!spec.isNull())
	{
		Json::Value node_name = spec["nodeName"];
		if(!node_name.isNull())
		{
			std::string nn = std::move(node_name.asString());
			if(!nn.empty())
			{
				pod.set_node_name(nn);
			}
		}
		Json::Value status = item["status"];
		if(!status.isNull())
		{
			Json::Value host_ip = status["hostIP"];
			if(!host_ip.isNull())
			{
				std::string hip = std::move(host_ip.asString());
				if(!hip.empty())
				{
					pod.set_host_ip(hip);
				}
			}
			Json::Value pod_ip = status["podIP"];
			if(!pod_ip.isNull())
			{
				std::string pip = std::move(pod_ip.asString());
				if(!pip.empty())
				{
					pod.set_internal_ip(pip);
				}
			}
		}
	}
}

void k8s_component::extract_services_data(const Json::Value& spec, k8s_service_t& service, const k8s_pods& pods)
{
	if(!spec.isNull())
	{
		Json::Value cluster_ip = spec["clusterIP"];
		if(!cluster_ip.isNull())
		{
			service.set_cluster_ip(cluster_ip.asString());
		}

		k8s_service_t::port_list pl;
		Json::Value ports = spec["ports"];
		if(!ports.isNull() && ports.isArray())
		{
			for (auto& port : ports)
			{
				k8s_service_t::net_port p;
				Json::Value json_port = port["port"];
				if(!json_port.isNull())
				{
					p.m_port = json_port.asUInt();
				}

				Json::Value json_protocol = port["protocol"];
				if(!json_protocol.isNull())
				{
					p.m_protocol = std::move(json_protocol.asString());
				}

				Json::Value json_target_port = port["targetPort"];
				if(!json_target_port.isNull())
				{
					if(json_target_port.isIntegral())
					{
						p.m_target_port = json_target_port.asUInt();
					}
					else if(json_target_port.isString())
					{
						std::string port_name = std::move(json_target_port.asString());
						std::vector<const k8s_pod_t*> pod_subset = service.get_selected_pods(pods);
						p.m_target_port = 0;
						for(const auto& pod : pod_subset)
						{
							const k8s_container::list& containers = pod->get_containers();
							for(const auto& container : containers)
							{
								const k8s_container::port* container_port = container.get_port(port_name);
								if(container_port)
								{
									p.m_target_port = container_port->get_port();
									break;
								}
								else
								{
									g_logger.log("Error while trying to determine port for service [" + service.get_name() + "]: "
												"no ports found for container [" + container.get_name() + "]", sinsp_logger::SEV_ERROR);
									p.m_target_port = 0;
								}
							}
						}
					}
					else
					{
						g_logger.log("Port of unknown or unsupported type.", sinsp_logger::SEV_ERROR);
						p.m_target_port = 0;
					}
				}

				Json::Value json_node_port = port["nodePort"];
				if(!json_node_port.isNull())
				{
					p.m_node_port = json_node_port.asUInt();
				}

				if(p.m_port && p.m_target_port)
				{
					pl.push_back(p);
				}
				else
				{
					// log warning
				}
			}
		}

		if(pl.size())
		{
			service.set_port_list(std::move(pl));
		}
	}
}


std::string k8s_component::get_name(type t)
{
	switch (t)
	{
	case K8S_NAMESPACES:
		return "namespaces";
	case K8S_NODES:
		return "nodes";
	case K8S_PODS:
		return "pods";
	case K8S_REPLICATIONCONTROLLERS:
		return "replicationcontrollers";
	case K8S_SERVICES:
		return "services";
	case K8S_COMPONENT_COUNT:
	default:
		break;
	}

	std::ostringstream os;
	os << "Unknown component type " << static_cast<int>(t);
	throw sinsp_exception(os.str().c_str());
}

k8s_component::type k8s_component::get_type(const std::string& name)
{
	if(name == "namespaces")
	{
		return K8S_NAMESPACES;
	}
	else if(name == "nodes")
	{
		return K8S_NODES;
	}
	else if(name == "pods")
	{
		return K8S_PODS;
	}
	else if(name == "replicationcontrollers")
	{
		return K8S_REPLICATIONCONTROLLERS;
	}
	else if(name == "services")
	{
		return K8S_SERVICES;
	}

	std::ostringstream os;
	os << "Unknown component name " << name;
	throw sinsp_exception(os.str().c_str());
}

k8s_pair_t* k8s_component::get_label(const k8s_pair_t& label)
{
	for (auto& lbl : m_labels)
	{
		if((lbl.first == label.first) && (lbl.second == label.second))
		{
			return &lbl;
		}
	}
	return 0;
}

void k8s_component::add_labels(k8s_pair_list&& labels)
{
	for (auto& label : labels)
	{
		if(!get_label(label))
		{
			emplace_label(std::move(label));
		}
	}
}

k8s_pair_t* k8s_component::get_selector(const k8s_pair_t& selector)
{
	for (auto& sel : m_selectors)
	{
		if((sel.first == selector.first) && (sel.second == selector.second))
		{
			return &sel;
		}
	}
	return 0;
}

void k8s_component::add_selectors(k8s_pair_list&& selectors)
{
	for (auto& selector : selectors)
	{
		if(!get_selector(selector))
		{
			emplace_selector(std::move(selector));
		}
	}
}

// TODO: proper selection process is more complicated, see “Labels and Selectors” at
// http://kubernetes.io/v1.0/docs/user-guide/labels.html
bool k8s_component::selector_in_labels(const k8s_pair_t& selector, const k8s_pair_list& labels) const
{
	for(const auto& label : labels)
	{
		if(label.first == selector.first && label.second == selector.second)
		{
			return true;
		}
	}
	return false;
}

bool k8s_component::selectors_in_labels(const k8s_pair_list& labels) const
{
	const k8s_pair_list& selectors = get_selectors();
	for(const auto& selector : selectors)
	{
		if(!selector_in_labels(selector, labels))
		{
			return false;
		}
	}
	return true;
}

//
// namespace
//
k8s_ns_t::k8s_ns_t(const std::string& name, const std::string& uid, const std::string& ns) :
	k8s_component(name, uid, ns)
{
}


//
// node
//

k8s_node_t::k8s_node_t(const std::string& name, const std::string& uid, const std::string& ns) :
	k8s_component(name, uid, ns)
{
}

k8s_node_t::host_ip_list k8s_node_t::extract_addresses(const Json::Value& status)
{
	host_ip_list address_list;
	if(!status.isNull())
	{
		Json::Value addresses = status["addresses"];
		if(!addresses.isNull() && addresses.isArray())
		{
			for (auto& address : addresses)
			{
				if(address.isObject())
				{
					Json::Value::Members addr_names_list = address.getMemberNames();
					for (auto& entry : addr_names_list)
					{
						if(entry == "address")
						{
							const Json::Value& ip = address[entry];
							if(!ip.isNull())
							{
								address_list.emplace(ip.asString());
							}
						}
					}
				}
			}
		}
	}
	return address_list;
}


//
// pod 
//

k8s_pod_t::k8s_pod_t(const std::string& name, const std::string& uid, const std::string& ns) :
	k8s_component(name, uid, ns), m_restart_count(0)
{
}

bool k8s_pod_t::has_container_id(const std::string& container_id)
{
	for(const auto& c : m_container_ids)
	{
		if(c == container_id) { return true; }
	}
	return false;
}

std::string* k8s_pod_t::get_container_id(const std::string& container_id)
{
	for(auto& c : m_container_ids)
	{
		if(c == container_id) { return &c; }
	}
	return 0;
}

k8s_container* k8s_pod_t::get_container(const std::string& container_name)
{
	for(auto& c : m_containers)
	{
		if(c.get_name() == container_name) { return &c; }
	}
	return 0;
}

//
// replication controller
//
k8s_rc_t::k8s_rc_t(const std::string& name, const std::string& uid, const std::string& ns) : 
	k8s_component(name, uid, ns)
{
}

std::vector<const k8s_pod_t*> k8s_rc_t::get_selected_pods(const std::vector<k8s_pod_t>& pods) const
{
	std::vector<const k8s_pod_t*> pod_vec;
	for(const auto& pod : pods)
	{
		if (selectors_in_labels(pod.get_labels()) && get_namespace() == pod.get_namespace())
		{
			pod_vec.push_back(&pod);
		}
	}
	return pod_vec;
}

int k8s_rc_t::get_replica(const Json::Value& item)
{
	if(!item.isNull())
	{
		const Json::Value& replicas = item["replicas"];
		if(!replicas.isNull() && replicas.isConvertibleTo(Json::intValue))
		{
			return replicas.asInt();
		}
	}
	g_logger.log("Can not determine number of replicas for K8s replication controller.", sinsp_logger::SEV_ERROR);
	return UNKNOWN_REPLICAS;
}

//
// service
//
k8s_service_t::k8s_service_t(const std::string& name, const std::string& uid, const std::string& ns) : 
	k8s_component(name, uid, ns)
{
}

std::vector<const k8s_pod_t*> k8s_service_t::get_selected_pods(const std::vector<k8s_pod_t>& pods) const
{
	std::vector<const k8s_pod_t*> pod_vec;
	for(const auto& pod : pods)
	{
		if (selectors_in_labels(pod.get_labels()) && get_namespace() == pod.get_namespace())
		{
			pod_vec.push_back(&pod);
		}
	}
	return pod_vec;
}

