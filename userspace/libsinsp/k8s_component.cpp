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
					entry_list.emplace_back(k8s_pair_s(member, val.asString()));
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

void k8s_component::extract_pod_data(const Json::Value& item, k8s_pod_s& pod)
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

std::vector<std::string> k8s_component::extract_nodes_addresses(const Json::Value& status)
{
	std::vector<std::string> address_list;
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
							Json::Value ip = address[entry];
							if(!ip.isNull())
							{
								address_list.emplace_back(std::move(ip.asString()));
							}
						}
					}
				}
			}
		}
	}
	return address_list;
}

void k8s_component::extract_services_data(const Json::Value& spec, k8s_service_s& service, const k8s_state_s::pods& pods)
{
	if(!spec.isNull())
	{
		Json::Value cluster_ip = spec["clusterIP"];
		if(!cluster_ip.isNull())
		{
			service.set_cluster_ip(cluster_ip.asString());
		}

		k8s_service_s::port_list pl;
		Json::Value ports = spec["ports"];
		if(!ports.isNull() && ports.isArray())
		{
			for (auto& port : ports)
			{
				k8s_service_s::net_port p;
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
						const k8s_pod_s* pod = service.get_selected_pod(pods);
						if(pod)
						{
							const k8s_container::list& containers = pod->get_containers();
							for(const auto& container : containers)
							{
								const k8s_container::port* container_port = container.get_port(port_name);
								if(container_port)
								{
									p.m_target_port = container_port->get_port();
								}
								else
								{
									g_logger.log("Error while trying to determine port for service [" + service.get_name() + "]: "
												"no ports found for container [" + container.get_name() + "]", sinsp_logger::SEV_ERROR);
									p.m_target_port = 0;
								}
							}
						}
						else
						{
							g_logger.log("Error while trying to determine service port: no pods available.", sinsp_logger::SEV_ERROR);
							p.m_target_port = 0;
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

k8s_pair_s* k8s_component::get_label(const k8s_pair_s& label)
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

k8s_pair_s* k8s_component::get_selector(const k8s_pair_s& selector)
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

//
// namespace
//
k8s_ns_s::k8s_ns_s(const std::string& name, const std::string& uid, const std::string& ns) :
	k8s_component(name, uid, ns)
{
}


//
// node
//

k8s_node_s::k8s_node_s(const std::string& name, const std::string& uid, const std::string& ns) :
	k8s_component(name, uid, ns)
{
}


//
// pod 
//

k8s_pod_s::k8s_pod_s(const std::string& name, const std::string& uid, const std::string& ns) :
	k8s_component(name, uid, ns)
{
}

bool k8s_pod_s::has_container_id(const std::string& container_id)
{
	for(const auto& c : m_container_ids)
	{
		if(c == container_id) { return true; }
	}
	return false;
}

std::string* k8s_pod_s::get_container_id(const std::string& container_id)
{
	for(auto& c : m_container_ids)
	{
		if(c == container_id) { return &c; }
	}
	return 0;
}

k8s_container* k8s_pod_s::get_container(const std::string& container_name)
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
k8s_rc_s::k8s_rc_s(const std::string& name, const std::string& uid, const std::string& ns) : 
	k8s_component(name, uid, ns)
{
}


//
// service
//
k8s_service_s::k8s_service_s(const std::string& name, const std::string& uid, const std::string& ns) : 
	k8s_component(name, uid, ns)
{
}

// TODO: proper selection process is more complicated, see “Labels and Selectors” at
// http://kubernetes.io/v1.0/docs/user-guide/labels.html
bool k8s_service_s::selector_in_labels(const k8s_pair_list& labels, const k8s_pair_s& selector)
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

const k8s_pod_s* k8s_service_s::get_selected_pod(const std::vector<k8s_pod_s>& pods)
{
	for(const auto& pod : pods)
	{
		for (const auto& selector : get_selectors())
		{
			if (selector_in_labels(pod.get_labels(), selector))
			{
				return &pod;
			}
		}
	}
	return 0;
}

//
// state
//

const std::string k8s_state_s::m_prefix = "docker://";

k8s_state_s::k8s_state_s()
{
}

// state/pods

void k8s_state_s::update_pod(k8s_pod_s& pod, const Json::Value& item, bool reset)
{
	k8s_pod_s::container_id_list container_ids = k8s_component::extract_pod_container_ids(item);
	k8s_container::list containers = k8s_component::extract_pod_containers(item);
	//TODO: consolidate (integrate IDs into containers)
	//ASSERT(container_ids.size() == containers.size());
	k8s_component::extract_pod_data(item, pod);
	if(reset) // initially, we just set everything
	{
		pod.set_container_ids(std::move(container_ids));
		pod.set_containers(std::move(containers));
	}
	else // update call
	{
		for(k8s_pod_s::container_id_list::iterator it = container_ids.begin(); it != container_ids.end();)
		{
			std::string* cid = pod.get_container_id(*it);
			if(cid && (*cid != *it))
			{
				*cid = *it;
				it = container_ids.erase(it);
			}
			else
			{
				++it;
			}
		}

		if(container_ids.size()) // what's left are new container IDs
		{
			pod.add_container_ids(std::move(container_ids));
		}

		for(k8s_pod_s::container_list::iterator it = containers.begin(); it != containers.end();)
		{
			k8s_container* c = pod.get_container(it->get_name());
			if(c && (*c != *it))
			{
				*c = *it;
				it = containers.erase(it);
			}
			else
			{
				++it;
			}
		}

		if(containers.size()) // what's left are new containers
		{
			pod.add_containers(std::move(containers));
		}
	}
	// cache pods by container ID
	for(const auto& container_id : container_ids)
	{
		cache_pod(container_id, pod);
	}
}

bool k8s_state_s::has_pod(k8s_pod_s& pod)
{
	for(const auto& p : m_pods)
	{
		if(p == pod) { return true; }
	}
	return false;
}

// state/general

void k8s_state_s::replace_items(k8s_component::type t, const std::string& name, const std::vector<k8s_pair_s>&& items)
{
	switch (t)
	{
	case k8s_component::K8S_NODES:
		if(name == "labels")
		{
			m_nodes.back().m_labels = std::move(items);
			return;
		}
		break;

	case k8s_component::K8S_NAMESPACES:
		if(name == "labels")
		{
			m_namespaces.back().m_labels = std::move(items);
			return;
		}
		break;

	case k8s_component::K8S_PODS:
		if(name == "labels")
		{
			m_pods.back().m_labels = std::move(items);
			return;
		}
		break;
	// only controllers and services can have selectors
	case k8s_component::K8S_REPLICATIONCONTROLLERS:
		if(name == "labels")
		{
			m_controllers.back().m_labels = std::move(items);
			return;
		}
		else if(name == "selector")
		{
			m_controllers.back().m_selectors = std::move(items);
			return;
		}
		break;

	case k8s_component::K8S_SERVICES:
		if(name == "labels")
		{
			m_services.back().m_labels = std::move(items);
			return;
		}
		else if(name == "selector")
		{
			m_services.back().m_selectors = std::move(items);
			return;
		}
		break;
	case k8s_component::K8S_COMPONENT_COUNT:
	default:
		break;
	}

	std::ostringstream os;
	os << "Unknown component type " << static_cast<int>(t) <<
		" or object name " << name;
	throw sinsp_exception(os.str().c_str());
}

k8s_component& k8s_state_s::add_common_single_value(k8s_component::type component, const std::string& name, const std::string& uid, const std::string& ns)
{
	switch (component)
	{
		case k8s_component::K8S_NODES:
			return get_component<nodes, k8s_node_s>(m_nodes, name, uid, ns);

		case k8s_component::K8S_NAMESPACES:
			return get_component<namespaces, k8s_ns_s>(m_namespaces, name, uid, ns);

		case k8s_component::K8S_PODS:
			return get_component<pods, k8s_pod_s>(m_pods, name, uid, ns);

		case k8s_component::K8S_REPLICATIONCONTROLLERS:
			return get_component<controllers, k8s_rc_s>(m_controllers, name, uid, ns);

		case k8s_component::K8S_SERVICES:
			return get_component<services, k8s_service_s>(m_services, name, uid, ns);

		case k8s_component::K8S_COMPONENT_COUNT:
		default:
			break;
	}

	std::ostringstream os;
	os << "Unknown component: " << component;
	throw sinsp_exception(os.str());
}

k8s_node_s* k8s_state_s::get_node(const std::string& uid)
{
	for (auto& node : m_nodes)
	{
		if(node.get_uid() == uid)
		{
			return &node;
		}
	}

	return nullptr;
}

void k8s_state_s::clear(k8s_component::type type)
{
	if(type == k8s_component::K8S_COMPONENT_COUNT)
	{
		m_namespaces.clear();
		m_nodes.clear();
		m_pods.clear();
		m_controllers.clear();
		m_services.clear();
	}
	else
	{
		switch (type)
		{
		case k8s_component::K8S_NODES:
			m_nodes.clear();
			break;
		case k8s_component::K8S_NAMESPACES:
			m_namespaces.clear();
			break;
		case k8s_component::K8S_PODS:
			m_pods.clear();
			break;
		case k8s_component::K8S_REPLICATIONCONTROLLERS:
			m_controllers.clear();
			break;
		case k8s_component::K8S_SERVICES:
			m_services.clear();
			break;
		case k8s_component::K8S_COMPONENT_COUNT:
		default:
			break;
		}
	}
}
