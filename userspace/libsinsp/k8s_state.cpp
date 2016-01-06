//
// k8s_state.cpp
//

#include "k8s_state.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include <sstream>
#include <iostream>

//
// state
//

#ifdef K8S_DISABLE_THREAD

const std::string k8s_state_t::m_prefix = "docker://";
const unsigned    k8s_state_t::m_id_length = 12u;

#endif // K8S_DISABLE_THREAD

k8s_state_t::k8s_state_t(bool is_captured) : m_is_captured(is_captured)
{
}

// state/pods

void k8s_state_t::update_pod(k8s_pod_t& pod, const Json::Value& item, bool reset)
{
	k8s_pod_t::container_id_list container_ids = k8s_component::extract_pod_container_ids(item);
	k8s_container::list containers = k8s_component::extract_pod_containers(item);

	k8s_component::extract_pod_data(item, pod);

	if(reset) // initially, we just set everything
	{
		pod.set_container_ids(std::move(container_ids));
		pod.set_containers(std::move(containers));
	}
	else // update call
	{
		for(k8s_pod_t::container_id_list::iterator it = container_ids.begin(); it != container_ids.end();)
		{
			if(pod.has_container_id(*it))
			{
				// ignoring container ID notification for an existing ID
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

		for(k8s_pod_t::container_list::iterator it = containers.begin(); it != containers.end();)
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
}

bool k8s_state_t::has_pod(k8s_pod_t& pod)
{
	for(const auto& p : m_pods)
	{
		if(p == pod) { return true; }
	}
	return false;
}

// state/general

void k8s_state_t::replace_items(k8s_component::type t, const std::string& name, const std::vector<k8s_pair_t>&& items)
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

k8s_component& k8s_state_t::add_common_single_value(k8s_component::type component, const std::string& name, const std::string& uid, const std::string& ns)
{
	switch (component)
	{
		case k8s_component::K8S_NODES:
			return get_component<k8s_nodes, k8s_node_t>(m_nodes, name, uid, ns);

		case k8s_component::K8S_NAMESPACES:
			return get_component<k8s_namespaces, k8s_ns_t>(m_namespaces, name, uid, ns);

		case k8s_component::K8S_PODS:
			return get_component<k8s_pods, k8s_pod_t>(m_pods, name, uid, ns);

		case k8s_component::K8S_REPLICATIONCONTROLLERS:
			return get_component<k8s_controllers, k8s_rc_t>(m_controllers, name, uid, ns);

		case k8s_component::K8S_SERVICES:
			return get_component<k8s_services, k8s_service_t>(m_services, name, uid, ns);

		case k8s_component::K8S_COMPONENT_COUNT:
		default:
			break;
	}

	std::ostringstream os;
	os << "Unknown component: " << component;
	throw sinsp_exception(os.str());
}

k8s_node_t* k8s_state_t::get_node(const std::string& uid)
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

void k8s_state_t::clear(k8s_component::type type)
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

// state/caching

void k8s_state_t::update_cache(const k8s_component::component_map::key_type& component)
{
#ifdef K8S_DISABLE_THREAD

	switch (component)
	{
		case k8s_component::K8S_NAMESPACES:
		{
			const k8s_namespaces& nspaces = get_namespaces();
			k8s_state_t::namespace_map& ns_map = get_namespace_map();
			ns_map.clear();
			for(const auto& ns : nspaces)
			{
				std::string ns_name = ns.get_name();
				if(!is_component_cached(ns_map, ns_name, &ns))
				{
					cache_component(ns_map, ns_name, &ns);
				}
				else
				{
					g_logger.log("Attempt to cache already cached NAMESPACE: " + ns_name, sinsp_logger::SEV_ERROR);
				}
			}
		}
		break;

		case k8s_component::K8S_PODS:
		{
			const k8s_pods& pods = get_pods();
			k8s_state_t::container_pod_map& container_pod_map = get_container_pod_map();
			container_pod_map.clear();
			for(const auto& pod : pods)
			{
				const k8s_pod_t::container_id_list& c_ids = pod.get_container_ids();
				for(const auto& c_id : c_ids)
				{
					if(!is_component_cached(container_pod_map, c_id, &pod))
					{
						cache_pod(container_pod_map, c_id, &pod);
					}
					else
					{
						g_logger.log("Attempt to cache already cached POD: " + c_id, sinsp_logger::SEV_ERROR);
					}
				}
			}
		}
		break;

		case k8s_component::K8S_REPLICATIONCONTROLLERS:
		{
			const k8s_controllers& rcs = get_rcs();
			const k8s_pods& pods = get_pods();
			k8s_state_t::pod_rc_map& pod_ctrl_map = get_pod_rc_map();
			pod_ctrl_map.clear();
			for(const auto& rc : rcs)
			{
				std::vector<const k8s_pod_t*> pod_subset = rc.get_selected_pods(pods);
				for(auto& pod : pod_subset)
				{
					const std::string& pod_uid = pod->get_uid();
					if(!is_component_cached(pod_ctrl_map, pod_uid, &rc))
					{
						cache_component(pod_ctrl_map, pod_uid, &rc);
					}
					else
					{
						g_logger.log("Attempt to cache already cached REPLICATION CONTROLLER: " + pod_uid, sinsp_logger::SEV_ERROR);
					}
				}
			}
		}
		break;

		case k8s_component::K8S_SERVICES:
		{
			const k8s_services& services = get_services();
			const k8s_pods& pods = get_pods();
			k8s_state_t::pod_service_map& pod_svc_map = get_pod_service_map();
			pod_svc_map.clear();
			for(const auto& service : services)
			{
				std::vector<const k8s_pod_t*> pod_subset = service.get_selected_pods(pods);
				for(auto& pod : pod_subset)
				{
					const std::string& pod_uid = pod->get_uid();
					if(!is_component_cached(pod_svc_map, pod_uid, &service))
					{
						cache_component(pod_svc_map, pod_uid, &service);
					}
					else
					{
						g_logger.log("Attempt to cache already cached SERVICE: " + pod_uid, sinsp_logger::SEV_ERROR);
					}
				}
			}
		}
		break;

		default: return;
	}

#endif // K8S_DISABLE_THREAD
}

