//
// k8s_component.cpp
//

#include "k8s_component.h"
#include "k8s_state.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "user_event.h"
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

const k8s_component::type_map k8s_component::list =
{
	{ k8s_component::K8S_NODES,                  "nodes"                  },
	{ k8s_component::K8S_NAMESPACES,             "namespaces"             },
	{ k8s_component::K8S_PODS,                   "pods"                   },
	{ k8s_component::K8S_REPLICATIONCONTROLLERS, "replicationcontrollers" },
	{ k8s_component::K8S_SERVICES,               "services"               },
	{ k8s_component::K8S_EVENTS,                 "events"                 }
};

k8s_component::k8s_component(type comp_type, const std::string& name, const std::string& uid, const std::string& ns) : 
	m_type(comp_type), m_name(name), m_uid(uid), m_ns(ns)
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
			std::string nn = node_name.asString();
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
				std::string hip = host_ip.asString();
				if(!hip.empty())
				{
					pod.set_host_ip(hip);
				}
			}
			Json::Value pod_ip = status["podIP"];
			if(!pod_ip.isNull())
			{
				std::string pip = pod_ip.asString();
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
					p.m_protocol = json_protocol.asString();
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
	case K8S_EVENTS:
		return "events";
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
	else if(name == "events")
	{
		return K8S_EVENTS;
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
	k8s_component(COMPONENT_TYPE, name, uid, ns)
{
}


//
// node
//

k8s_node_t::k8s_node_t(const std::string& name, const std::string& uid, const std::string& ns) :
	k8s_component(COMPONENT_TYPE, name, uid, ns)
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
	k8s_component(COMPONENT_TYPE, name, uid, ns)
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
	k8s_component(COMPONENT_TYPE, name, uid, ns)
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
	k8s_component(COMPONENT_TYPE, name, uid, ns)
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

//
// event
//

k8s_event_t::k8s_event_t(const std::string& name, const std::string& uid, const std::string& ns) :
	k8s_component(COMPONENT_TYPE, name, uid, ns),
	m_name_translation
	{
		//
		// Event translations, based on:
		// https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/container/event.go
		// https://github.com/kubernetes/kubernetes/blob/master/pkg/controller/controller_utils.go
		// https://github.com/kubernetes/kubernetes/blob/master/pkg/controller/node/nodecontroller.go
		// https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/kubelet.go
		//

		//
		// Node
		//

		// Node Controller
		{ "TerminatedAllPods",     "Terminated All Pods"},
		{ "RegisteredNode",        "Node Registered"},
		{ "RemovingNode",          "Removing Node"},
		{ "DeletingNode",          "Deleting Node"},
		{ "DeletingAllPods",       "Deleting All Pods"},
		{ "TerminatingEvictedPod", "Terminating Evicted Pod" },

		// Kubelet
		{ "NodeReady",               "Node Ready"                 },
		{ "NodeNotReady",            "Node not Ready"             },
		{ "NodeSchedulable",         "Node is Schedulable"        },
		{ "NodeNotSchedulable",      "Node is not Schedulable"    },
		{ "CIDRNotAvailable",        "CIDR not Available"         },
		{ "CIDRAssignmentFailed",    "CIDR Assignment Failed"     },
		{ "Starting",                "Starting Kubelet"           },
		{ "KubeletSetupFailed",      "Kubelet Setup Failed"       },
		{ "FailedMount",             "Volume Mount Failed"        },
		{ "NodeSelectorMismatching", "Node Selector Mismatch"     },
		{ "InsufficientFreeCPU",     "Insufficient Free CPU"      },
		{ "InsufficientFreeMemory",  "Insufficient Free Memory"   },
		{ "OutOfDisk",               "Out of Disk"                },
		{ "HostNetworkNotSupported", "Host Network not Supported" },
		{ "NilShaper",               "Undefined Shaper"           },
		{ "Rebooted",                "Node Rebooted"              },
		{ "NodeHasSufficientDisk",   "Node Has Sufficient Disk"   },
		{ "NodeOutOfDisk",           "Node Out of Disk Space"     },

		// Image manager
		{ "InvalidDiskCapacity", "Invalid Disk Capacity"  },
		{ "FreeDiskSpaceFailed", "Free Disk Space Failed" },

		//
		// Pod
		//

		// Image
		{ "Pulling",           "Pulling Image"                                },
		{ "Pulled",            "Image Pulled"                                 },
		{ "Failed",            "Container Image Pull, Create or Start Failed" },
		{ "InspectFailed",     "Image Inspect Failed"                         },
		{ "ErrImageNeverPull", "Image NeverPull Policy Error"                 },
		{ "BackOff",           "Back Off Container Start or Image Pull"       },

		//{ "OutOfDisk" ,"Out of Disk" }, duplicate

		// Container
		{ "Created", "Container Created"                },
		{ "Started", "Container Started"                },
		//{ "Failed",  "Container Create or Start Failed" }, duplicate
		{ "Killing", "Killing Container"                },

		//{ "BackOff", "Backoff Start Container" }, duplicate

		// Probe
		{ "Unhealthy", "Container Unhealthy" },

		// Pod worker
		{ "FailedSync", "Pod Sync Failed" },

		// Config
		{ "FailedValidation", "Failed Configuration Validation" },
		{ "HostPortConflict", "Host/Port Conflict"              },

		//
		// Replication Controller
		//
		{ "SuccessfulCreate",  "Pod Created"      },
		{ "FailedCreate",      "Pod Create Failed"},
		{ "SuccessfulDelete",  "Pod Deleted"      },
		{ "FailedDelete",      "Pod Delete Failed"}
	}
{
}

void k8s_event_t::update(const Json::Value& item, k8s_state_t& state)
{
#ifndef _WIN32

	time_t     epoch_time_s = 0;
	string     event_name;
	string     description;
	severity_t severity = sinsp_logger::SEV_EVT_INFORMATION;
	string     scope;
	tag_map_t  tags;

	const Json::Value& obj = item["involvedObject"];
	if(g_logger.get_severity() >= sinsp_logger::SEV_TRACE)
	{
		g_logger.log("K8s EVENT: \n" + json_as_string(item), sinsp_logger::SEV_TRACE);
	}
	if(!obj.isNull())
	{
		std::string sev = get_json_string(item, "type");
		// currently, only "Normal" and "Warning"
		severity = sinsp_logger::SEV_EVT_INFORMATION;
		if(sev == "Warning") { severity = sinsp_logger::SEV_EVT_WARNING; }
		if(g_logger.get_severity() >= sinsp_logger::SEV_TRACE)
		{
			g_logger.log("K8s EVENT:"
						"\nnamespace = " + get_json_string(obj, "namespace") +
						"\nname = " + get_json_string(obj, "name") +
						"\nuid = " + get_json_string(obj, "uid") +
						"\ntype = " + get_json_string(obj, "kind") +
						"\nseverity = " + get_json_string(item, "type") + " (" + std::to_string(severity) + ')', sinsp_logger::SEV_TRACE);
		}
	}
	else
	{
		g_logger.log("K8s event: cannot get involved object (null)", sinsp_logger::SEV_ERROR);
		return;
	}

	std::string ts = get_json_string(item , "lastTimestamp");
	if(!ts.empty())
	{
		if((epoch_time_s = get_epoch_utc_seconds(ts)) == (time_t) -1)
		{
			g_logger.log("K8s event: cannot convert [" + ts + "] to epoch timestamp", sinsp_logger::SEV_ERROR);
		}
		g_logger.log("K8s EVENT update: time:" + std::to_string(epoch_time_s), sinsp_logger::SEV_DEBUG);
	}
	else
	{
		g_logger.log("K8s event: cannot convert time (null, empty or not string)", sinsp_logger::SEV_ERROR);
	}
	event_name = get_json_string(item , "reason");
	const auto& translation = m_name_translation.find(event_name);
	if(translation != m_name_translation.end())
	{
		event_name = translation->second;
	}
	description = get_json_string(item, "message");
	g_logger.log("K8s EVENT message:" + description, sinsp_logger::SEV_DEBUG);

	// Although it's easier and more efficient to obtain the involved object data from
	// the event itself, there is a downside - event may not carry the data in the
	// same format as reported in metadata protobuf (generated from k8s state);
	// an example is IP address vs. DNS name for node, there may be other cases.
	// For that reason, we try to obtain info about involved object from state; if object is
	// not found in state (due to undefined arrival order of event and metadata messages),
	// we get scope data from the event itself.
	string component_uid = get_json_string(obj, "uid");
	if(!component_uid.empty())
	{
		std::string t;
		const k8s_component* comp = state.get_component(component_uid, &t);
		if(comp && !t.empty())
		{
			std::string node_name = comp->get_node_name();
			if(!node_name.empty())
			{
				if(scope.length()) { scope.append(" and "); }
				scope.append("kubernetes.node.name=").append(node_name);
			}
			const std::string& ns = comp->get_namespace();
			if(!ns.empty())
			{
				if(scope.length()) { scope.append(" and "); }
				scope.append("kubernetes.namespace.name=").append(ns);
			}
			if(scope.length()) { scope.append(" and "); }
			scope.append("kubernetes.").append(t).append(".name=").append(comp->get_name());
			/* no labels for now
			for(const auto& label : comp->get_labels())
			{
				tags[label.first] = label.second;
				g_logger.log("EVENT label: [" + label.first + ':' + label.second + ']', sinsp_logger::SEV_DEBUG);
				scope.append(" and kubernetes.").append(t).append(".label.").append(label.first).append(1, '=').append(label.second);
			}*/
		}
		else
		{
			g_logger.log("K8s event: cannot obtain component (UID not found: [" + component_uid +
						 "]), trying to build scope directly from event ...", sinsp_logger::SEV_WARNING);
			make_scope(obj, scope);
		}
	}
	else
	{
		g_logger.log("K8s event: cannot obtain component UID, trying to build scope directly from event ...",
					 sinsp_logger::SEV_WARNING);
		make_scope(obj, scope);
	}

	tags["source"] = "kubernetes";
	g_logger.log(sinsp_user_event::to_string(epoch_time_s, std::move(event_name), std::move(description),
											std::move(scope), std::move(tags)), severity);

	// TODO: sysdig capture?
#endif // _WIN32
}

void k8s_event_t::make_scope_impl(const Json::Value& obj, std::string comp, std::string& scope, bool ns)
{
	if(ns)
	{
		std::string ns_name = get_json_string(obj, "namespace");
		if(!ns_name.empty())
		{
			if(scope.length()) { scope.append(" and "); }
			scope.append("kubernetes.namespace.name=").append(ns_name);
		}
	}
	if(comp.length() && ci_compare::is_equal(get_json_string(obj, "kind"), comp))
	{
		std::string comp_name = get_json_string(obj, "name");
		if(!comp_name.empty())
		{
			if(scope.length()) { scope.append(" and "); }
			comp[0] = tolower(comp[0]);
			scope.append("kubernetes.").append(comp).append(".name=").append(comp_name);
		}
		if(comp_name.empty())
		{
			g_logger.log("K8s " + comp + " event detected but " + comp + " name could not be determined. Scope will be empty.", sinsp_logger::SEV_WARNING);
		}
	}
	else
	{
		g_logger.log("K8s event detected but component name was empty. Scope will be empty.", sinsp_logger::SEV_WARNING);
	}
}

void k8s_event_t::make_scope(const Json::Value& obj, std::string& scope)
{
	if(ci_compare::is_equal(get_json_string(obj, "kind"), "Pod"))
	{
		make_scope_impl(obj, "Pod", scope);
	}
	else if(ci_compare::is_equal(get_json_string(obj, "kind"), "ReplicationController"))
	{
		make_scope_impl(obj, "ReplicationController", scope);
	}
	else if(ci_compare::is_equal(get_json_string(obj, "kind"), "Node"))
	{
		make_scope_impl(obj, "Node", scope, false);
	}
}
