//
// k8s.cpp
//

#include "k8s.h"
#include "k8s_component.h"
#include "k8s_dispatcher.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include <sstream>
#include <utility>
#include <memory>
#include <algorithm>
#include <iostream>

const k8s_component::component_map k8s::m_components =
{
	{ k8s_component::K8S_NODES,                  "nodes"                  },
	{ k8s_component::K8S_NAMESPACES,             "namespaces"             },
	{ k8s_component::K8S_PODS,                   "pods"                   },
	{ k8s_component::K8S_REPLICATIONCONTROLLERS, "replicationcontrollers" },
	{ k8s_component::K8S_SERVICES,               "services"               }
};

k8s::dispatch_map k8s::make_dispatch_map(k8s_state_s& state, std::mutex& mut)
{
	return dispatch_map
	{
		{ k8s_component::K8S_NODES,                  new k8s_dispatcher(k8s_component::K8S_NODES,                  state, mut) },
		{ k8s_component::K8S_NAMESPACES,             new k8s_dispatcher(k8s_component::K8S_NAMESPACES,             state, mut) },
		{ k8s_component::K8S_PODS,                   new k8s_dispatcher(k8s_component::K8S_PODS,                   state, mut) },
		{ k8s_component::K8S_REPLICATIONCONTROLLERS, new k8s_dispatcher(k8s_component::K8S_REPLICATIONCONTROLLERS, state, mut) },
		{ k8s_component::K8S_SERVICES,               new k8s_dispatcher(k8s_component::K8S_SERVICES,               state, mut) }
	};
}

k8s::k8s(const std::string& uri, bool watch, const std::string& api) : m_net(*this, uri, api),
		m_watch(watch),
		m_own_proto(true),
		m_dispatch(make_dispatch_map(m_state, m_mutex))
{
	get_state(true);
}

k8s::~k8s()
{
	if(m_watch)
	{
		m_net.stop_watching();
	}

	for (auto& update : m_dispatch)
	{
		delete update.second;
	}

	if(m_own_proto)
	{
	}
}

void k8s::build_state()
{
	std::ostringstream os;
	for (auto& component : m_components)
	{
		{
			std::lock_guard<std::mutex> lock(m_mutex);
			m_state.clear(component.first);
		}
		m_net.get_all_data(component, os);
		parse_json(os.str(), component);
		os.str("");
	}
}

const k8s_state_s& k8s::get_state(bool rebuild)
{
	try
	{
		if(rebuild)
		{
			build_state();
		}
	}
	catch (std::exception& ex)
	{
		g_logger.log(ex.what());
		throw;
	}
	return m_state;
}

void k8s::start_watching()
{
	if(m_watch && !m_net.is_watching())
	{
		m_net.start_watching();
	}
}

void k8s::stop_watching()
{
	if(m_net.is_watching())
	{
		m_net.stop_watching();
	}
}

void k8s::on_watch_data(k8s_event_data&& msg)
{
	m_dispatch[msg.component()]->enqueue(std::move(msg));
}

std::size_t k8s::count(k8s_component::type component) const
{
	std::lock_guard<std::mutex> lock(m_mutex);

	switch (component)
	{
	case k8s_component::K8S_NODES:
		return m_state.get_nodes().size();

	case k8s_component::K8S_NAMESPACES:
		return m_state.get_namespaces().size();

	case k8s_component::K8S_PODS:
		return m_state.get_pods().size();

	case k8s_component::K8S_REPLICATIONCONTROLLERS:
		return m_state.get_rcs().size();

	case k8s_component::K8S_SERVICES:
		return m_state.get_services().size();

	case k8s_component::K8S_COMPONENT_COUNT:
	default:
		break;
	}

	std::ostringstream os;
	os << "Unknown component " << static_cast<int>(component);
	throw std::invalid_argument(os.str());
}

void k8s::extract_data(const Json::Value& items, k8s_component::type component)
{
	if(items.isArray())
	{
		for (auto& item : items)
		{
			Json::Value obj = item["metadata"];
			if(obj.isObject())
			{
				std::lock_guard<std::mutex> lock(m_mutex);

				Json::Value ns = obj["namespace"];
				std::string nspace;
				if(!ns.isNull())
				{
					nspace = ns.asString();
				}
				m_state.add_common_single_value(component, obj["name"].asString(), obj["uid"].asString(), nspace);

				Json::Value metadata = item["metadata"];
				if(!metadata.isNull())
				{
					std::vector<k8s_pair_s> entries = k8s_component::extract_object(metadata, "labels");
					if(entries.size() > 0)
					{
						m_state.replace_items(component, "labels", std::move(entries));
					}
				}

				Json::Value spec = item["spec"];
				if(!spec.isNull())
				{
					std::vector<k8s_pair_s> entries = k8s_component::extract_object(spec, "selector");
					if(entries.size() > 0)
					{
						m_state.replace_items(component, "selector", std::move(entries));
					}
				}

				if(component == k8s_component::K8S_NODES)
				{
					std::vector<std::string> addresses = k8s_component::extract_nodes_addresses(item["status"]);
					for (auto&& address : addresses)
					{
						m_state.add_last_node_ip(std::move(address));
					}
				}
				else if(component == k8s_component::K8S_PODS)
				{
					k8s_pod_s::container_list containers = k8s_component::extract_pod_containers(item);
					m_state.get_pods().back().set_container_ids(std::move(containers));
					k8s_component::extract_pod_data(item, m_state.get_pods().back());
				}
				else if(component == k8s_component::K8S_SERVICES)
				{
					k8s_component::extract_services_data(item["spec"], m_state.get_services().back());
				}
			}
		}
	}
}

void k8s::parse_json(const std::string& json, const k8s_component::component_map::value_type& component)
{
	Json::Value root;
	Json::Reader reader;
	if(reader.parse(json, root, false))
	{
		Json::Value items = root["items"];
		if(!root.isNull())
		{
			extract_data(items, component.first);
			//g_logger.log(root.toStyledString(), sinsp_logger::SEV_DEBUG);
		}
		else
		{
			throw std::invalid_argument("Invalid JSON");
		}
	}
	else
	{
		throw std::runtime_error("JSON parsing failed");
	}
}
