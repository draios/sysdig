//
// k8s_dispatcher.cpp
//

#include "k8s_dispatcher.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include <assert.h>
#include <stdexcept>
#include <algorithm>
#include <sstream>
#include <iostream>


k8s_dispatcher::k8s_dispatcher(k8s_component::type t, k8s_state_t& state
#ifndef K8S_DISABLE_THREAD
	,std::mutex& mut
#endif
	) :
	m_type(t),
	m_state(state)
#ifndef K8S_DISABLE_THREAD
	,m_mutex(mut)
#endif
{
}

void k8s_dispatcher::enqueue(k8s_event_data&& event_data)
{
	assert(event_data.component() == m_type);

	std::string&& data = event_data.data();

	if(m_messages.size() == 0)
	{
		m_messages.push_back("");
	}

	std::string* msg = &m_messages.back();
	std::string::size_type pos = msg->find_first_of('\n');
	
	// previous msg full, this is a beginning of new message
	if(pos != std::string::npos && pos == (msg->size() - 1))
	{
		m_messages.push_back("");
		msg = &m_messages.back();
	}

	while ((pos = data.find_first_of('\n')) != std::string::npos)
	{
		msg->append((data.substr(0, pos + 1)));
		data = data.substr(pos + 1);
		m_messages.push_back("");
		msg = &m_messages.back();
	};

	if(data.size() > 0)
	{
		msg->append((data));
	}

	dispatch(); // candidate for separate thread
}

bool k8s_dispatcher::is_valid(const std::string& msg)
{
	// zero-length message is valid because that's how it starts its life.
	// so, here we only check for messages that are single newline only
	// or those that are longer than one character and contain multiple newlines.

	if((msg.size() == 1 && msg[0] == '\n') ||
		std::count(msg.begin(), msg.end(), '\n') > 1)
	{
		return false;
	}
	return true;
}

bool k8s_dispatcher::is_ready(const std::string& msg)
{
	// absurd minimum ( "{}\n" ) but it's hard to tell 
	// what minimal size is, so there ...
	if(msg.size() < 3) 
	{
		return false;
	}
	return msg[msg.size() - 1] == '\n';
}

k8s_dispatcher::msg_data k8s_dispatcher::get_msg_data(Json::Value& root)
{
	msg_data data;
	Json::Value evtype = root["type"];
	if(!evtype.isNull())
	{
		const std::string& et = evtype.asString();
		if(!et.empty())
		{
			if(et[0] == 'A') { data.m_reason = COMPONENT_ADDED;    }
			else if(et[0] == 'M') { data.m_reason = COMPONENT_MODIFIED; }
			else if(et[0] == 'D') { data.m_reason = COMPONENT_DELETED;  }
			else if(et[0] == 'E') { data.m_reason = COMPONENT_ERROR;    }
		}
		else
		{
			return msg_data();
		}
	}
	Json::Value object = root["object"];

	// +++ for capture
	Json::Value kind = object["kind"];
	if(!kind.isNull() && kind.isString() && root["kind"].isNull())
	{
		root["kind"] = kind.asString();
	}
	Json::Value api_version = object["apiVersion"];
	if(!api_version.isNull() && api_version.isString() && root["apiVersion"].isNull())
	{
		root["apiVersion"] = api_version.asString();
	}
	// --- for capture

	if(!object.isNull() && object.isObject())
	{
		Json::Value meta = object["metadata"];
		if(!meta.isNull() && meta.isObject())
		{
			Json::Value name = meta["name"];
			if(!name.isNull())
			{
				data.m_name = std::move(name.asString());
			}
			Json::Value uid = meta["uid"];
			if(!uid.isNull())
			{
				data.m_uid = std::move(uid.asString());
			}
			Json::Value nspace = meta["namespace"];
			if(!nspace.isNull())
			{
				data.m_namespace = std::move(nspace.asString());
			}
		}
	}
	return data;
}

void k8s_dispatcher::log_error(const Json::Value& root, const std::string& comp)
{
	std::string unk_err = "Unknown.";
	std::ostringstream os;
	os << "K8S server reported " << comp << " error: ";
	if(!root.isNull())
	{
		Json::Value object = root["object"];
		if(!object.isNull())
		{
			os << object.toStyledString();
			unk_err.clear();
		}
	}
	os << unk_err;
	g_logger.log(os.str(), sinsp_logger::SEV_ERROR);
}

void k8s_dispatcher::handle_node(const Json::Value& root, const msg_data& data)
{
	K8S_LOCK_GUARD_MUTEX;

	if(data.m_reason == COMPONENT_ADDED)
	{
		if(m_state.has(m_state.get_nodes(), data.m_uid))
		{
			std::ostringstream os;
			os << "ADDED message received for existing node [" << data.m_uid << "], updating only.";
			g_logger.log(os.str(), sinsp_logger::SEV_INFO);
		}
		k8s_node_t& node = m_state.get_component<k8s_nodes, k8s_node_t>(m_state.get_nodes(), data.m_name, data.m_uid);
		const Json::Value& object = root["object"];
		if(!object.isNull())
		{
			const Json::Value& status = object["status"];
			if(!status.isNull())
			{
				k8s_node_t::host_ip_list addresses = k8s_node_t::extract_addresses(status);
				if(addresses.size() > 0)
				{
					node.set_host_ips(std::move(addresses));
				}
			}
			Json::Value metadata = object["metadata"];
			if(!metadata.isNull())
			{
				k8s_pair_list entries = k8s_component::extract_object(metadata, "labels");
				if(entries.size() > 0)
				{
					node.set_labels(std::move(entries));
				}
			}
		}
	}
	else if(data.m_reason == COMPONENT_MODIFIED)
	{
		if(!m_state.has(m_state.get_nodes(), data.m_uid))
		{
			std::ostringstream os;
			os << "MODIFIED message received for non-existing node [" << data.m_uid << "], giving up.";
			g_logger.log(os.str(), sinsp_logger::SEV_ERROR);
			return;
		}
		k8s_node_t& node = m_state.get_component<k8s_nodes, k8s_node_t>(m_state.get_nodes(), data.m_name, data.m_uid);
		Json::Value object = root["object"];
		if(!object.isNull())
		{
			const Json::Value& status = object["status"];
			if(!status.isNull())
			{
				k8s_node_t::host_ip_list addresses = k8s_node_t::extract_addresses(status);
				if(addresses.size() > 0)
				{
					node.set_host_ips(std::move(addresses));
				}
			}
			const Json::Value& metadata = object["metadata"];
			if(!metadata.isNull())
			{
				k8s_pair_list entries = k8s_component::extract_object(metadata, "labels");
				if(entries.size() > 0)
				{
					node.add_labels(std::move(entries));
				}
			}
		}
	}
	else if(data.m_reason == COMPONENT_DELETED)
	{
		if(!m_state.delete_component(m_state.get_nodes(), data.m_uid))
		{
			g_logger.log(std::string("NODE not found: ") + data.m_name, sinsp_logger::SEV_ERROR);
		}
	}
	else if(data.m_reason == COMPONENT_ERROR)
	{
		log_error(root, "NODE");
	}
	else
	{
		g_logger.log(std::string("Unsupported K8S NODE event reason: ") + std::to_string(data.m_reason), sinsp_logger::SEV_ERROR);
	}
}

void k8s_dispatcher::handle_namespace(const Json::Value& root, const msg_data& data)
{
	K8S_LOCK_GUARD_MUTEX;

	if(data.m_reason == COMPONENT_ADDED)
	{
		if(m_state.has(m_state.get_namespaces(), data.m_uid))
		{
			std::ostringstream os;
			os << "ADDED message received for existing namespace [" << data.m_uid << "], updating only.";
			g_logger.log(os.str(), sinsp_logger::SEV_INFO);
		}
		k8s_ns_t& ns = m_state.get_component<k8s_namespaces, k8s_ns_t>(m_state.get_namespaces(), data.m_name, data.m_uid);
		const Json::Value& object = root["object"];
		if(!object.isNull())
		{
			const Json::Value& metadata = object["metadata"];
			if(!metadata.isNull())
			{
				k8s_pair_list entries = k8s_component::extract_object(metadata, "labels");
				if(entries.size() > 0)
				{
					ns.set_labels(std::move(entries));
				}
			}
		}
	}
	else if(data.m_reason == COMPONENT_MODIFIED)
	{
		if(!m_state.has(m_state.get_namespaces(), data.m_uid))
		{
			std::ostringstream os;
			os << "MODIFIED message received for non-existing namespace [" << data.m_uid << "], giving up.";
			g_logger.log(os.str(), sinsp_logger::SEV_ERROR);
			return;
		}
		k8s_ns_t& ns = m_state.get_component<k8s_namespaces, k8s_ns_t>(m_state.get_namespaces(), data.m_name, data.m_uid);
		const Json::Value& object = root["object"];
		if(!object.isNull())
		{
			const Json::Value& metadata = object["metadata"];
			if(!metadata.isNull())
			{
				k8s_pair_list entries = k8s_component::extract_object(metadata, "labels");
				if(entries.size() > 0)
				{
					ns.add_labels(std::move(entries));
				}
			}
		}
	}
	else if(data.m_reason == COMPONENT_DELETED)
	{
		if(!m_state.delete_component(m_state.get_namespaces(), data.m_uid))
		{
			g_logger.log(std::string("NAMESPACE not found: ") + data.m_name, sinsp_logger::SEV_ERROR);
		}
	}
	else if(data.m_reason == COMPONENT_ERROR)
	{
		log_error(root, "NAMESPACE");
	}
	else
	{
		g_logger.log(std::string("Unsupported K8S NAMESPACE event reason: ") + std::to_string(data.m_reason), sinsp_logger::SEV_ERROR);
	}
}

void k8s_dispatcher::handle_pod(const Json::Value& root, const msg_data& data)
{
	K8S_LOCK_GUARD_MUTEX;

	if(data.m_reason == COMPONENT_ADDED)
	{
		const Json::Value& object = root["object"];
		if(!object.isNull())
		{
			if(m_state.has(m_state.get_pods(), data.m_uid))
			{
				std::ostringstream os;
				os << "ADDED message received for existing pod [" << data.m_uid << "], updating only.";
				g_logger.log(os.str(), sinsp_logger::SEV_INFO);
			}
			k8s_pod_t& pod = m_state.get_component<k8s_pods, k8s_pod_t>(m_state.get_pods(), data.m_name, data.m_uid, data.m_namespace);
			handle_labels(pod, object["metadata"], "labels");
			m_state.update_pod(pod, object, false);
		}
	}
	else if(data.m_reason == COMPONENT_MODIFIED)
	{
		const Json::Value& object = root["object"];
		if(!object.isNull())
		{
			if(!m_state.has(m_state.get_pods(), data.m_uid))
			{
				std::ostringstream os;
				os << "MODIFIED message received for non-existing pod [" << data.m_uid << "], giving up.";
				g_logger.log(os.str(), sinsp_logger::SEV_ERROR);
				return;
			}
			k8s_pod_t& pod = m_state.get_component<k8s_pods, k8s_pod_t>(m_state.get_pods(), data.m_name, data.m_uid, data.m_namespace);
			handle_labels(pod, object["metadata"], "labels");
			m_state.update_pod(pod, object, false);
		}
	}
	else if(data.m_reason == COMPONENT_DELETED)
	{
		k8s_pod_t* pod = m_state.get_component<k8s_pods, k8s_pod_t>(m_state.get_pods(), data.m_uid);
		if(pod)
		{
			if(!m_state.delete_component(m_state.get_pods(), data.m_uid))
			{
				g_logger.log(std::string("Error deleting POD: ") + data.m_name, sinsp_logger::SEV_ERROR);
			}
		}
		else
		{
			g_logger.log(std::string("POD not found: ") + data.m_name, sinsp_logger::SEV_WARNING);
		}
	}
	else if(data.m_reason == COMPONENT_ERROR)
	{
		log_error(root, "POD");
	}
	else
	{
		g_logger.log(std::string("Unsupported K8S POD event reason: ") + std::to_string(data.m_reason), sinsp_logger::SEV_ERROR);
	}
}

void k8s_dispatcher::handle_rc(const Json::Value& root, const msg_data& data)
{
	K8S_LOCK_GUARD_MUTEX;

	if(data.m_reason == COMPONENT_ADDED)
	{
		if(m_state.has(m_state.get_rcs(), data.m_uid))
		{
			std::ostringstream os;
			os << "ADDED message received for existing replication controller [" << data.m_uid << "], updating only.";
			g_logger.log(os.str(), sinsp_logger::SEV_INFO);
		}
		k8s_rc_t& rc = m_state.get_component<k8s_controllers, k8s_rc_t>(m_state.get_rcs(), data.m_name, data.m_uid, data.m_namespace);
		const Json::Value& object = root["object"];
		if(!object.isNull())
		{
			handle_labels(rc, object["metadata"], "labels");
			handle_selectors(rc, object["spec"], "selector");
			rc.set_replicas(object);
		}
	}
	else if(data.m_reason == COMPONENT_MODIFIED)
	{
		if(!m_state.has(m_state.get_rcs(), data.m_uid))
		{
			std::ostringstream os;
			os << "MODIFIED message received for non-existing replication controller [" << data.m_uid << "], giving up.";
			g_logger.log(os.str(), sinsp_logger::SEV_ERROR);
			return;
		}
		k8s_rc_t& rc = m_state.get_component<k8s_controllers, k8s_rc_t>(m_state.get_rcs(), data.m_name, data.m_uid, data.m_namespace);
		const Json::Value& object = root["object"];
		if(!object.isNull())
		{
			handle_labels(rc, object["metadata"], "labels");
			handle_selectors(rc, object["spec"], "selector");
			rc.set_replicas(object);
		}
	}
	else if(data.m_reason == COMPONENT_DELETED)
	{
		if(!m_state.delete_component(m_state.get_rcs(), data.m_uid))
		{
			g_logger.log(std::string("CONTROLLER not found: ") + data.m_name, sinsp_logger::SEV_ERROR);
		}
	}
	else if(data.m_reason == COMPONENT_ERROR)
	{
		log_error(root, "REPLICATION CONTROLLER");
	}
	else
	{
		g_logger.log(std::string("Unsupported K8S REPLICATION CONTROLLER event reason: ") + std::to_string(data.m_reason), sinsp_logger::SEV_ERROR);
	}
}

void k8s_dispatcher::handle_service(const Json::Value& root, const msg_data& data)
{
	K8S_LOCK_GUARD_MUTEX;

	if(data.m_reason == COMPONENT_ADDED)
	{
		const Json::Value& object = root["object"];
		if(!object.isNull())
		{
			if(m_state.has(m_state.get_services(), data.m_uid))
			{
				std::ostringstream os;
				os << "ADDED message received for existing service [" << data.m_uid << "], updating only.";
				g_logger.log(os.str(), sinsp_logger::SEV_INFO);
			}
			k8s_service_t& service = m_state.get_component<k8s_services, k8s_service_t>(m_state.get_services(), data.m_name, data.m_uid, data.m_namespace);
			handle_labels(service, object["metadata"], "labels");
			k8s_component::extract_services_data(object, service, m_state.get_pods());
		}
	}
	else if(data.m_reason == COMPONENT_MODIFIED)
	{
		const Json::Value& object = root["object"];
		if(!object.isNull())
		{
			if(!m_state.has(m_state.get_services(), data.m_uid))
			{
				std::ostringstream os;
				os << "MODIFIED message received for non-existing service [" << data.m_uid << "], giving up.";
				g_logger.log(os.str(), sinsp_logger::SEV_ERROR);
				return;
			}
			k8s_service_t& service = m_state.get_component<k8s_services, k8s_service_t>(m_state.get_services(), data.m_name, data.m_uid, data.m_namespace);
			handle_labels(service, object["metadata"], "labels");
			k8s_component::extract_services_data(object, service, m_state.get_pods());
		}
	}
	else if(data.m_reason == COMPONENT_DELETED)
	{
		if(!m_state.delete_component(m_state.get_services(), data.m_uid))
		{
			g_logger.log(std::string("SERVICE not found: ") + data.m_name, sinsp_logger::SEV_ERROR);
		}
	}
	else if(data.m_reason == COMPONENT_ERROR)
	{
		log_error(root, "SERVICE");
	}
	else
	{
		g_logger.log(std::string("Unsupported K8S SERVICE event reason: ") + std::to_string(data.m_reason), sinsp_logger::SEV_ERROR);
	}
}

void k8s_dispatcher::extract_data(const std::string& json, bool enqueue)
{
	Json::Value root;
	Json::Reader reader;
	if(reader.parse(json, root, false))
	{
		std::ostringstream os;
		msg_data data = get_msg_data(root);
		if(data.is_valid())
		{
			std::ostringstream os;
			os << '[' << to_reason_desc(data.m_reason) << ',';
			switch (m_type)
			{
				case k8s_component::K8S_NODES:
					os << "NODE,";
					handle_node(root, data);
					break;
				case k8s_component::K8S_NAMESPACES:
					os << "NAMESPACE,";
					handle_namespace(root, data);
					break;
				case k8s_component::K8S_PODS:
					os << "POD,";
					handle_pod(root, data);
					break;
				case k8s_component::K8S_REPLICATIONCONTROLLERS:
					os << "REPLICATION_CONTROLLER,";
					handle_rc(root, data);
					break;
				case k8s_component::K8S_SERVICES:
					os << "SERVICE,";
					handle_service(root, data);
					break;
				default:
				{
					std::ostringstream eos;
					eos << "Unknown component: " << static_cast<int>(m_type);
					throw sinsp_exception(os.str());
				}
			}
			os << data.m_name << ',' << data.m_uid << ',' << data.m_namespace << ']';
			g_logger.log(os.str(), sinsp_logger::SEV_INFO);
			//g_logger.log(root.toStyledString(), sinsp_logger::SEV_DEBUG);
			{
				K8S_LOCK_GUARD_MUTEX;
				m_state.update_cache(m_type);
#ifdef HAS_CAPTURE
				if(enqueue)
				{
					m_state.enqueue_capture_event(root);
				}
#endif
			}
		}
	}
	else
	{
		g_logger.log("Bad JSON message received :[" + json + ']', sinsp_logger::SEV_ERROR);
	}
}

void k8s_dispatcher::dispatch()
{
	for (list::iterator it = m_messages.begin(); it != m_messages.end();)
	{
		if(is_ready(*it))
		{
			extract_data(*it, true);
			it = m_messages.erase(it);
		}
		else
		{
			++it;
		}
	}
}

std::string k8s_dispatcher::to_reason_desc(msg_reason reason)
{
	switch (reason)
	{
	case COMPONENT_ADDED:
		return "ADDED";
	case COMPONENT_MODIFIED:
		return "MODIFIED";
	case COMPONENT_DELETED:
		return "DELETED";
	case COMPONENT_ERROR:
		return "ERROR";
	case COMPONENT_UNKNOWN:
		return "UNKNOWN";
	default:
		return "";
	}
}

k8s_dispatcher::msg_reason k8s_dispatcher::to_reason(const std::string& desc)
{
	if(desc == "ADDED") { return COMPONENT_ADDED; }
	else if(desc == "MODIFIED") { return COMPONENT_MODIFIED; }
	else if(desc == "DELETED") { return COMPONENT_DELETED; }
	else if(desc == "ERROR") { return COMPONENT_ERROR; }
	else if(desc == "UNKNOWN") { return COMPONENT_UNKNOWN; }
	throw sinsp_exception(desc);
}
