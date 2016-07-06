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

k8s_component::type_map k8s::m_components;

k8s::dispatch_map k8s::make_dispatch_map(k8s_state_t& state, ext_list_ptr_t extensions)
{
	dispatch_map dm;
	dm.insert({ k8s_component::K8S_NODES,                  new k8s_dispatcher(k8s_component::K8S_NODES,                  state) });
	dm.insert({ k8s_component::K8S_NAMESPACES,             new k8s_dispatcher(k8s_component::K8S_NAMESPACES,             state) });
	dm.insert({ k8s_component::K8S_PODS,                   new k8s_dispatcher(k8s_component::K8S_PODS,                   state) });
	dm.insert({ k8s_component::K8S_REPLICATIONCONTROLLERS, new k8s_dispatcher(k8s_component::K8S_REPLICATIONCONTROLLERS, state) });
	dm.insert({ k8s_component::K8S_SERVICES,               new k8s_dispatcher(k8s_component::K8S_SERVICES,               state) });

	if(m_event_filter)
	{
		dm.insert({ k8s_component::K8S_EVENTS, new k8s_dispatcher(k8s_component::K8S_EVENTS, state, m_event_filter) });
	}

	if(extensions)
	{
		dm.insert({ k8s_component::K8S_REPLICASETS, new k8s_dispatcher(k8s_component::K8S_REPLICASETS, state) });
		dm.insert({ k8s_component::K8S_DAEMONSETS,  new k8s_dispatcher(k8s_component::K8S_DAEMONSETS,  state) });
		dm.insert({ k8s_component::K8S_DEPLOYMENTS, new k8s_dispatcher(k8s_component::K8S_DEPLOYMENTS, state) });
	}

	return dm;
}

k8s::k8s(const std::string& uri, bool start_watch, bool watch_in_thread, bool is_captured,
		//const std::string& api,
#ifdef HAS_CAPTURE
		ssl_ptr_t ssl, bt_ptr_t bt,
#endif // HAS_CAPTURE
		bool curl_debug,
		filter_ptr_t event_filter,
		ext_list_ptr_t extensions) :
		m_watch(uri.empty() ? false : start_watch),
		m_state(is_captured),
		m_event_filter(event_filter),
		m_dispatch(std::move(make_dispatch_map(m_state, extensions))),
		m_watch_in_thread(watch_in_thread)
#ifdef HAS_CAPTURE
		,m_net(uri.empty() ? 0 : new k8s_net(*this, uri, ssl, bt, curl_debug, extensions))
#endif
{
	g_logger.log(std::string("Creating K8s object for [" +
							 (uri.empty() ? std::string("capture replay") : uri) + ']'),
							 sinsp_logger::SEV_DEBUG);
	if(m_components.empty())
	{
		m_components.insert({ k8s_component::K8S_NODES,                  "nodes"                  });
		m_components.insert({ k8s_component::K8S_NAMESPACES,             "namespaces"             });
		m_components.insert({ k8s_component::K8S_PODS,                   "pods"                   });
		m_components.insert({ k8s_component::K8S_REPLICATIONCONTROLLERS, "replicationcontrollers" });
		m_components.insert({ k8s_component::K8S_SERVICES,               "services"               });
		if(event_filter)
		{
			m_components.insert({ k8s_component::K8S_EVENTS, "events"});
		}
		if(extensions)
		{
			m_components.insert({ k8s_component::K8S_DAEMONSETS,  "daemonsets"  });
			m_components.insert({ k8s_component::K8S_DEPLOYMENTS, "deployments" });
			m_components.insert({ k8s_component::K8S_REPLICASETS, "replicasets" });
		}
	}

	if (!uri.empty())
	{
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
	m_net = 0;
#endif
}

void k8s::build_state()
{
#ifdef HAS_CAPTURE
	if(m_net)
	{
		std::ostringstream os;
		for (auto& component : m_components)
		{
			// events are transient and fetching all data for events would pull
			// old events on agent restart, causing unecessary network and DB
			// traffic; so, we only add watch interface here for events
			if(component.first != k8s_component::K8S_EVENTS)
			{
				m_state.clear(component.first);
				ASSERT(m_net);
				m_net->get_all_data(component, os);
				parse_json(os.str(), component);
				os.str("");
			}
			else if(m_event_filter)
			{
				m_net->add_api_interface(component);
			}
		}
	}
	else
	{
		throw sinsp_exception("K8s net object is null.");
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
	if(m_watch)
	{
		m_net->watch();
	}
#endif
}

void k8s::on_watch_data(k8s_event_data&& msg)
{
	k8s_component::type comp = msg.component();
	auto it = m_dispatch.find(comp);
	if(it != m_dispatch.end() && it->second)
	{
		it->second->enqueue(std::move(msg));
	}
	else
	{
		g_logger.log("K8s: Cannot enqueue " + k8s_component::get_name(comp) + " message (dispatcher is null)", sinsp_logger::SEV_WARNING);
	}
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
			else if(type == "ReplicaSet")            { component_type = k8s_component::K8S_REPLICASETS;            }
			else if(type == "Service")               { component_type = k8s_component::K8S_SERVICES;               }
			else if(type == "DaemonSet")             { component_type = k8s_component::K8S_DAEMONSETS;             }
			else if(type == "Deployment")            { component_type = k8s_component::K8S_DEPLOYMENTS;            }
			else if(type == "EventList")             { component_type = k8s_component::K8S_EVENTS;                 }
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
	m_dispatch[component_type]->extract_data(root, false);
}

std::size_t k8s::count(k8s_component::type component) const
{
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

	case k8s_component::K8S_REPLICASETS:
		return m_state.get_rss().size();

	case k8s_component::K8S_SERVICES:
		return m_state.get_services().size();

	case k8s_component::K8S_DAEMONSETS:
		return m_state.get_daemonsets().size();

	case k8s_component::K8S_DEPLOYMENTS:
		return m_state.get_deployments().size();

	case k8s_component::K8S_EVENTS:
		return m_state.get_events().size();

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
		for (auto& item : items)
		{
			const Json::Value& metadata = item["metadata"];
			if(!metadata.isNull())
			{
				const Json::Value& ns = metadata["namespace"];
				std::string nspace;
				if(!ns.isNull() && ns.isString())
				{
					nspace = ns.asString();
				}
				const Json::Value& name = metadata["name"];
				if(!name.isNull() && name.isString())
				{
					Json::Value uid = metadata["uid"];
					if(!uid.isNull() && uid.isString())
					{
						m_state.add_common_single_value(component, name.asString(), uid.asString(), nspace);
					}
					else
					{
						throw sinsp_exception("K8s extract_data(): uid is null or not a string.");
					}
				}
				else
				{
					throw sinsp_exception("K8s extract_data(): name is null or not a string.");
				}

				std::vector<k8s_pair_t> entries = k8s_component::extract_object(metadata, "labels");
				if(entries.size() > 0)
				{
					m_state.replace_items(component, "labels", std::move(entries));
				}
			}

			const Json::Value& spec = item["spec"];
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
						m_state.update_pod(pod, item);
					}
				}
				break;

			case k8s_component::K8S_SERVICES:
				if(!spec.isNull())
				{
					k8s_services& svcs = m_state.get_services();
					if(svcs.size())
					{
						k8s_service_t& svc = svcs.back();
						component_kind = "Service";
						component_name = svc.get_name();
						component_uid = svc.get_uid();
						component_ns = svc.get_namespace();
						k8s_component::extract_services_data(spec, svc, m_state.get_pods());
					}
				}
				break;

			case k8s_component::K8S_REPLICATIONCONTROLLERS:
				{
					k8s_controllers& rcs = m_state.get_rcs();
					if(rcs.size())
					{
						k8s_rc_t& rc = rcs.back();
						component_kind = "ReplicationController";
						component_name = rc.get_name();
						component_uid = rc.get_uid();
						k8s_dispatcher::handle_labels(rc, metadata, "labels");
						k8s_dispatcher::handle_selectors(rc, spec);
						rc.set_replicas(item);
					}
					break;
				}

			case k8s_component::K8S_REPLICASETS:
				{
					k8s_replicasets& rss = m_state.get_rss();
					if(rss.size())
					{
						k8s_rs_t& rs = rss.back();
						component_kind = "ReplicaSet";
						component_name = rs.get_name();
						component_uid = rs.get_uid();
						k8s_dispatcher::handle_labels(rs, metadata, "labels");
						k8s_dispatcher::handle_selectors(rs, spec);
						rs.set_replicas(item);
					}
					break;
				}

			case k8s_component::K8S_DAEMONSETS:
				{
					k8s_daemonsets& daemonsets = m_state.get_daemonsets();
					if(daemonsets.size())
					{
						k8s_daemonset_t& daemonset = daemonsets.back();
						component_kind = "DaemonSet";
						component_name = daemonset.get_name();
						component_uid = daemonset.get_uid();
						k8s_dispatcher::handle_labels(daemonset, metadata, "labels");
						k8s_dispatcher::handle_selectors(daemonset, spec);
						daemonset.set_scheduled(item);
					}
					break;
				}

			case k8s_component::K8S_DEPLOYMENTS:
				{
					k8s_deployments& deployments = m_state.get_deployments();
					if(deployments.size())
					{
						k8s_deployment_t& deployment = deployments.back();
						component_kind = "Deployment";
						component_name = deployment.get_name();
						component_uid = deployment.get_uid();
						k8s_dispatcher::handle_labels(deployment, metadata, "labels");
						k8s_dispatcher::handle_selectors(deployment, spec);
						deployment.set_replicas(item);
					}
					break;
				}

			case k8s_component::K8S_EVENTS:
				if(m_event_filter)
				{
					k8s_events& evts = m_state.get_events();
					if(evts.size())
					{
						component_kind = "Event";
						component_name = evts.back().get_name();
						component_uid = evts.back().get_uid();
						component_ns = evts.back().get_namespace();
						k8s_event_t& evt = evts.back();
						m_state.update_event(evt, item);
					}
					break;
				}

			default: break;
			}
			os.str("");
			if(!component_kind.empty())
			{
				os << '[' << event_type << ',' << component_kind << ',' <<
							component_name << ',' << component_uid << ',' << component_ns << ']';
				g_logger.log(os.str(), sinsp_logger::SEV_INFO);
			}
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

void k8s::parse_json(const std::string& json, const k8s_component::type_map::value_type& component)
{
	Json::Value root;
	Json::Reader reader;
	if(reader.parse(json, root, false))
	{
		//g_logger.log(root.toStyledString(), sinsp_logger::SEV_TRACE);
		Json::Value items = root["items"];
		if(!items.isNull())
		{
			Json::Value api_version = root["apiVersion"];
			std::string api_ver = api_version.isNull() ? std::string() : api_version.asString();
			extract_data(items, component.first, api_ver);
			m_state.update_cache(component.first);
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
