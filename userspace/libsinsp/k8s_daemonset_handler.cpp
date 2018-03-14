//
// k8s_daemonset_handler.cpp
//
#ifndef CYGWING_AGENT

#include "k8s_daemonset_handler.h"
#include "sinsp.h"
#include "sinsp_int.h"

// filters normalize state and event JSONs, so they can be processed generically:
// event is turned into a single-entry array, state is turned into an array of ADDED events

std::string k8s_daemonset_handler::EVENT_FILTER =
	"{"
	" type: .type,"
	" apiVersion: .object.apiVersion,"
	" kind: .object.kind,"
	" items:"
	" ["
	"  .object |"
	"  {"
	"   namespace: .metadata.namespace,"
	"   name: .metadata.name,"
	"   uid: .metadata.uid,"
	"   timestamp: .metadata.creationTimestamp,"
	"   desiredScheduled: .status.desiredNumberScheduled,"
	"   currentScheduled: .status.currentNumberScheduled,"
	"   selector: .spec.selector.matchLabels,"
	"   labels: .metadata.labels"
	"  }"
	" ]"
	"}";

std::string k8s_daemonset_handler::STATE_FILTER =
	"{"
	" type: \"ADDED\","
	" apiVersion: .apiVersion,"
	" kind: \"DaemonSet\", "
	" items:"
	" ["
	"  .items[] | "
	"  {"
	"   namespace: .metadata.namespace,"
	"   name: .metadata.name,"
	"   uid: .metadata.uid,"
	"   timestamp: .metadata.creationTimestamp,"
	"   desiredScheduled: .status.desiredNumberScheduled,"
	"   currentScheduled: .status.currentNumberScheduled,"
	"   selector: .spec.selector.matchLabels,"
	"   labels: .metadata.labels"
	"   }"
	" ]"
	"}";

std::string k8s_daemonset_handler::NULL_FILTER =
	"{"
	" type: \"NONEXISTENT\","
	" apiVersion: .apiVersion,"
	" kind: \"DaemonSet\", "
	" items: [ null ]"
	"}";

k8s_daemonset_handler::k8s_daemonset_handler(k8s_state_t& state
#ifdef HAS_CAPTURE
	,ptr_t dependency_handler
	,collector_ptr_t collector
	,std::string url
	,const std::string& http_version
	,ssl_ptr_t ssl
	,bt_ptr_t bt
	,bool connect
	,bool blocking_socket
#endif // HAS_CAPTURE
	):
		k8s_handler("k8s_daemonset_handler", true,
#ifdef HAS_CAPTURE
					url,
					"/apis/extensions/v1beta1/daemonsets",
					STATE_FILTER, EVENT_FILTER, NULL_FILTER, collector,
					http_version, 1000L, ssl, bt, true,
					connect, dependency_handler, blocking_socket,
#endif // HAS_CAPTURE
					100, // max msgs
					&state)
{
}

k8s_daemonset_handler::~k8s_daemonset_handler()
{
}

bool k8s_daemonset_handler::handle_component(const Json::Value& json, const msg_data* data)
{
	if(data)
	{
		if(m_state)
		{
			if((data->m_reason == k8s_component::COMPONENT_ADDED) ||
			   (data->m_reason == k8s_component::COMPONENT_MODIFIED))
			{
				k8s_daemonset_t& ds =
					m_state->get_component<k8s_daemonsets, k8s_daemonset_t>(m_state->get_daemonsets(),
																  data->m_name, data->m_uid, data->m_namespace);
				k8s_pair_list entries = extract_object(json["labels"]);
				if(entries.size() > 0)
				{
					ds.set_labels(std::move(entries));
				}
				handle_selectors(ds, json["selector"]);
				const Json::Value& desired = json["desiredScheduled"];
				const Json::Value& current = json["currentScheduled"];
				if(!desired.isNull() && desired.isConvertibleTo(Json::intValue) &&
				   !current.isNull() && current.isConvertibleTo(Json::intValue))
				{
					ds.set_scheduled(desired.asInt(), current.asInt());
				}
			}
			else if(data->m_reason == k8s_component::COMPONENT_DELETED)
			{
				if(!m_state->delete_component(m_state->get_daemonsets(), data->m_uid))
				{
					log_not_found(*data);
					return false;
				}
			}
			else if(data->m_reason != k8s_component::COMPONENT_ERROR)
			{
				g_logger.log(std::string("Unsupported K8S " + name() + " event reason: ") +
							 std::to_string(data->m_reason), sinsp_logger::SEV_ERROR);
				return false;
			}
		}
		else
		{
			throw sinsp_exception("K8s node handler: state is null.");
		}
	}
	else
	{
		throw sinsp_exception("K8s node handler: data is null.");
	}
	return true;
}
#endif // CYGWING_AGENT
