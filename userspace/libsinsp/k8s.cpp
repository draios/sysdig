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
	k8s::dispatch_map k8s::make_dispatch_map(k8s_state_t& state)
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
	k8s::dispatch_map k8s::make_dispatch_map(k8s_state_t& state, std::mutex& mut)
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

k8s::k8s(const std::string& uri, bool start_watch, bool watch_in_thread, bool is_captured,
		const std::string& api,
#ifdef HAS_CAPTURE
		ssl_ptr_t ssl, bt_ptr_t bt,
#endif // HAS_CAPTURE
		bool curl_debug) :
		m_watch(uri.empty() ? false : start_watch),
		m_watch_in_thread(uri.empty() ? false : start_watch && watch_in_thread),
		m_state(is_captured),
#ifndef K8S_DISABLE_THREAD
		m_dispatch(std::move(make_dispatch_map(m_state, m_mutex))),
#else
		m_dispatch(std::move(make_dispatch_map(m_state)))
#endif
#ifdef HAS_CAPTURE
		,m_net(uri.empty() ? 0 : new k8s_net(*this, uri, api, ssl, bt, curl_debug))
#endif
{
	if (!uri.empty())
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
			cleanup();
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
	cleanup();
}

void k8s::stop_watch()
{
#ifdef HAS_CAPTURE
	if(m_watch)
	{
		ASSERT(m_net);
		m_net->stop_watching();
	}
#endif
}

void k8s::cleanup()
{
	for (auto& update : m_dispatch)
	{
		delete update.second;
	}
#ifdef HAS_CAPTURE
	delete m_net;
#endif
}

void k8s::build_state()
{
#ifdef HAS_CAPTURE
	std::ostringstream os;
	for (auto& component : m_components)
	{
		{
			K8S_LOCK_GUARD_MUTEX;
			m_state.clear(component.first);
		}
		ASSERT(m_net);
		m_net->get_all_data(component, os);
		parse_json(os.str(), component);
		os.str("");
	}
#endif
}

const k8s_state_t& k8s::get_state(bool rebuild)
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
#ifdef HAS_CAPTURE
	ASSERT(m_net);
	if((m_watch && !m_net->is_watching()) || !m_watch_in_thread)
	{
		m_net->watch();
	}
#endif
}

void k8s::stop_watching()
{
#ifdef HAS_CAPTURE
	ASSERT(m_net);
	if(m_net->is_watching())
	{
		m_net->stop_watching();
	}
#endif
}

void k8s::on_watch_data(k8s_event_data&& msg)
{
	m_dispatch[msg.component()]->enqueue(std::move(msg));
}

void k8s::simulate_watch_event(const std::string& json)
{
	Json::Value root;
	Json::Reader reader;
	k8s_component::type component_type = k8s_component::K8S_COMPONENT_COUNT;
	if(reader.parse(json, root, false))
	{
		Json::Value kind = root["kind"];
		if(!kind.isNull() && kind.isString())
		{
			std::string type = kind.asString();
			if(type == "Namespace")                  { component_type = k8s_component::K8S_NAMESPACES;             }
			else if(type == "Node")                  { component_type = k8s_component::K8S_NODES;                  }
			else if(type == "Pod")                   { component_type = k8s_component::K8S_PODS;                   }
			else if(type == "ReplicationController") { component_type = k8s_component::K8S_REPLICATIONCONTROLLERS; }
			else if(type == "Service")               { component_type = k8s_component::K8S_SERVICES;               }
			else
			{
				g_logger.log("Unrecognized component type: " + type, sinsp_logger::SEV_ERROR);
				return;
			}
		}
		else
		{
			g_logger.log("Component type not found in JSON", sinsp_logger::SEV_ERROR);
			return;
		}
	}
	else
	{
		g_logger.log("Error parsing JSON", sinsp_logger::SEV_ERROR);
		return;
	}

	ASSERT(component_type < k8s_component::K8S_COMPONENT_COUNT);
	m_dispatch[component_type]->extract_data(json, false);
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

void k8s::extract_data(Json::Value& items, k8s_component::type component, const std::string& api_version)
{
	if(api_version.empty())
	{
		throw sinsp_exception("API version not provided.");
	}

	std::ostringstream os;
	const std::string event_type = "ADDED";
	std::string component_kind, component_name, component_uid, component_ns;

	if(items.isArray())
	{
		K8S_LOCK_GUARD_MUTEX;
		for (auto& item : items)
		{
			Json::Value metadata = item["metadata"];
			if(!metadata.isNull())
			{
				Json::Value ns = metadata["namespace"];
				std::string nspace;
				if(!ns.isNull())
				{
					nspace = ns.asString();
				}
				m_state.add_common_single_value(component, metadata["name"].asString(), metadata["uid"].asString(), nspace);

				std::vector<k8s_pair_t> entries = k8s_component::extract_object(metadata, "labels");
				if(entries.size() > 0)
				{
					m_state.replace_items(component, "labels", std::move(entries));
				}
			}

			Json::Value spec = item["spec"];
			if(!spec.isNull())
			{
				std::vector<k8s_pair_t> entries = k8s_component::extract_object(spec, "selector");
				if(entries.size() > 0)
				{
					m_state.replace_items(component, "selector", std::move(entries));
				}
			}

			component_kind.clear();
			component_name.clear();
			component_uid.clear();
			switch(component)
			{
			case k8s_component::K8S_NAMESPACES:
				{
					const k8s_namespaces& nss = m_state.get_namespaces();
					if(nss.size())
					{
						component_kind = "Namespace";
						component_name = nss.back().get_name();
						component_uid = nss.back().get_uid();
					}
				}
				break;

			case k8s_component::K8S_NODES:
				{
					Json::Value status = item["status"];
					if(!status.isNull())
					{
						const k8s_nodes& nds = m_state.get_nodes();
						if(nds.size())
						{
							component_kind = "Node";
							component_name = nds.back().get_name();
							component_uid = nds.back().get_uid();
							k8s_node_t::host_ip_list addresses = k8s_node_t::extract_addresses(status);
							for(std::string address : addresses)
							{
								m_state.add_last_node_ip(std::move(address));
							}
						}
					}
				}
				break;

			case k8s_component::K8S_PODS:
				{
					k8s_pods& p = m_state.get_pods();
					if(p.size())
					{
						component_kind = "Pod";
						component_name = p.back().get_name();
						component_uid = p.back().get_uid();
						component_ns = p.back().get_namespace();
						k8s_pod_t& pod = p.back();
						m_state.update_pod(pod, item, true);
					}
				}
				break;

			case k8s_component::K8S_SERVICES:
				if(!spec.isNull())
				{
					k8s_services& svcs = m_state.get_services();
					if(svcs.size())
					{
						component_kind = "Service";
						component_name = svcs.back().get_name();
						component_uid = svcs.back().get_uid();
						component_ns = svcs.back().get_namespace();
						k8s_component::extract_services_data(spec, svcs.back(), m_state.get_pods());
					}
				}
				break;

			case k8s_component::K8S_REPLICATIONCONTROLLERS:
				{
					const k8s_controllers& rcs = m_state.get_rcs();
					if(rcs.size())
					{
						component_kind = "ReplicationController";
						component_name = rcs.back().get_name();
						component_uid = rcs.back().get_uid();
					}
					break;
				}

			default: break;
			}
			os.str("");
			os << '[' << event_type << ',' << component_kind << ',' << 
						component_name << ',' << component_uid << ',' << component_ns << ']';
			g_logger.log(os.str(), sinsp_logger::SEV_INFO);
#ifdef HAS_CAPTURE
			ASSERT(!component_kind.empty());
			item["apiVersion"] = api_version;
			item["kind"] = component_kind;
			Json::Value new_item;
			new_item["type"] = event_type;
			new_item["object"] = item;
			new_item["apiVersion"] = api_version;
			new_item["kind"] = component_kind;
			m_state.enqueue_capture_event(new_item);
#endif // HAS_CAPTURE
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
		if(!items.isNull())
		{
			Json::Value api_version = root["apiVersion"];
			std::string api_ver = api_version.isNull() ? std::string() : api_version.asString();
			extract_data(items, component.first, api_ver);
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
