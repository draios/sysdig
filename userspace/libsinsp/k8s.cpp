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

#ifdef K8S_DISABLE_THREAD
	k8s::dispatch_map k8s::make_dispatch_map(k8s_state_s& state)
	{
		return dispatch_map
		{
			{ k8s_component::K8S_NODES,                  new k8s_dispatcher(k8s_component::K8S_NODES,                  state)},
			{ k8s_component::K8S_NAMESPACES,             new k8s_dispatcher(k8s_component::K8S_NAMESPACES,             state)},
			{ k8s_component::K8S_PODS,                   new k8s_dispatcher(k8s_component::K8S_PODS,                   state)},
			{ k8s_component::K8S_REPLICATIONCONTROLLERS, new k8s_dispatcher(k8s_component::K8S_REPLICATIONCONTROLLERS, state)},
			{ k8s_component::K8S_SERVICES,               new k8s_dispatcher(k8s_component::K8S_SERVICES,               state)}
		};
	}
#else
	k8s::dispatch_map k8s::make_dispatch_map(k8s_state_s& state, std::mutex& mut)
	{
		return dispatch_map
		{
			{ k8s_component::K8S_NODES,                  new k8s_dispatcher(k8s_component::K8S_NODES,                  state, mut)},
			{ k8s_component::K8S_NAMESPACES,             new k8s_dispatcher(k8s_component::K8S_NAMESPACES,             state, mut)},
			{ k8s_component::K8S_PODS,                   new k8s_dispatcher(k8s_component::K8S_PODS,                   state, mut)},
			{ k8s_component::K8S_REPLICATIONCONTROLLERS, new k8s_dispatcher(k8s_component::K8S_REPLICATIONCONTROLLERS, state, mut)},
			{ k8s_component::K8S_SERVICES,               new k8s_dispatcher(k8s_component::K8S_SERVICES,               state, mut)}
		};
	}
#endif // K8S_DISABLE_THREAD

k8s::k8s(const std::string& uri, bool start_watch, bool watch_in_thread, const std::string& api) :
		m_watch(start_watch),
		m_watch_in_thread(start_watch && watch_in_thread),
		m_own_proto(true),
	#ifndef K8S_DISABLE_THREAD
		m_dispatch(std::move(make_dispatch_map(m_state, m_mutex))),
	#else
		m_dispatch(std::move(make_dispatch_map(m_state))),
	#endif
		m_net(*this, uri, api)
{
	if (uri.empty())
	{
		g_logger.log("Empty URI received (unexpected condition in production environment).", sinsp_logger::SEV_CRITICAL);
	}
	else
	{
#ifdef K8S_DISABLE_THREAD
		if(watch_in_thread)
		{
			g_logger.log("Watching in thread requested but not available (only available in multi-thread build).", sinsp_logger::SEV_WARNING);
		}
#endif // K8S_DISABLE_THREAD
		try
		{
			get_state(true);
		}
		catch (...)
		{
			clean_dispatch();
			throw;
		}

		if(m_watch)
		{
			watch();
		}
	}
}

k8s::~k8s()
{
	stop_watch();
	clean_dispatch();
}

void k8s::stop_watch()
{
	if(m_watch)
	{
		m_net.stop_watching();
	}
}

void k8s::clean_dispatch()
{
	for (auto& update : m_dispatch)
	{
		delete update.second;
	}
}

void k8s::build_state()
{
	std::ostringstream os;
	for (auto& component : m_components)
	{
		{
			K8S_LOCK_GUARD_MUTEX;
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
		g_logger.log(ex.what(), sinsp_logger::SEV_ERROR);
		throw;
	}
	return m_state;
}

void k8s::watch()
{
	if((m_watch && !m_net.is_watching()) || !m_watch_in_thread)
	{
		m_net.watch();
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
	K8S_LOCK_GUARD_MUTEX;

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
	throw sinsp_exception(os.str());
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
				K8S_LOCK_GUARD_MUTEX;
				Json::Value ns = obj["namespace"];
				std::string nspace;
				if(!ns.isNull())
				{
					nspace = std::move(ns.asString());
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
					k8s_pod_s& pod = m_state.get_pods().back();
					m_state.update_pod(pod, item, true);
				}
				else if(component == k8s_component::K8S_SERVICES)
				{
					k8s_component::extract_services_data(item["spec"], m_state.get_services().back(), m_state.get_pods());
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
			{
				K8S_LOCK_GUARD_MUTEX;
				m_state.update_cache(component.first);
			}
		}
		else
		{
			throw sinsp_exception("Invalid JSON");
		}
	}
	else
	{
		throw sinsp_exception("JSON parsing failed");
	}
}
