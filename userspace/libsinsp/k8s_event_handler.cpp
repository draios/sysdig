//
// k8s_event_handler.cpp
//

#include "k8s_event_handler.h"
#include "sinsp.h"
#include "sinsp_int.h"

// filters normalize state and event JSONs, so they can be processed generically:
// event is turned into a single-entry array, state is turned into an array of ADDED events

std::string k8s_event_handler::EVENT_FILTER =
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
	"   lastTimestamp: .lastTimestamp,"
	"   reason: .reason,"
	"   message: .message,"
	"   involvedObject: .involvedObject"
	"  }"
	" ]"
	"}";

std::string k8s_event_handler::STATE_FILTER =
	"{"
	" type: \"ADDED\","
	" apiVersion: .apiVersion,"
	" kind: \"Event\","
	" items:"
	" ["
	"  .items[] |"
	"  {"
	"   namespace: .metadata.namespace,"
	"   name: .metadata.name,"
	"   uid: .metadata.uid,"
	"   timestamp: .metadata.creationTimestamp,"
	"   lastTimestamp: .lastTimestamp,"
	"   reason: .reason,"
	"   message: .message,"
	"   involvedObject: .involvedObject"
	"  }"
	" ]"
	"}";

k8s_event_handler::k8s_event_handler(k8s_state_t& state,
	collector_ptr_t collector,
	std::string url,
	const std::string& http_version,
	ssl_ptr_t ssl,
	bt_ptr_t bt,
	bool connect,
	filter_ptr_t event_filter):
		k8s_handler("k8s_event_handler", true,
					url, "/api/v1/events",
					STATE_FILTER, EVENT_FILTER, collector,
					http_version, 1000L, ssl, bt, &state, true, connect),
		m_event_filter(event_filter)
{
}

k8s_event_handler::~k8s_event_handler()
{
}

bool k8s_event_handler::handle_component(const Json::Value& json, const msg_data* data)
{
	if(m_event_filter)
	{
		if(m_state)
		{
			if(data)
			{
				if((data->m_reason == k8s_component::COMPONENT_ADDED) ||
				   (data->m_reason == k8s_component::COMPONENT_MODIFIED))
				{
					g_logger.log("K8s EVENT: handling event.", sinsp_logger::SEV_TRACE);
					const Json::Value& involved_object = json["involvedObject"];
					if(!involved_object.isNull())
					{
						bool is_aggregate = (get_json_string(json , "message").find("events with common reason combined") != std::string::npos);
						time_t last_ts = get_epoch_utc_seconds(get_json_string(json , "lastTimestamp"));
						time_t now_ts = get_epoch_utc_seconds_now();
						g_logger.log("K8s EVENT: lastTimestamp=" + std::to_string(last_ts) + ", now_ts=" + std::to_string(now_ts), sinsp_logger::SEV_TRACE);
						if(((last_ts > 0) && (now_ts > 0)) && // we got good timestamps
							!is_aggregate && // not an aggregated cached event
							((now_ts - last_ts) < 10)) // event not older than 10 seconds
						{
							const Json::Value& kind = involved_object["kind"];
							const Json::Value& event_reason = json["reason"];
							g_logger.log("K8s EVENT: involved object and event reason found:" + kind.asString() + '/' + event_reason.asString(), sinsp_logger::SEV_TRACE);
							if(!kind.isNull() && kind.isConvertibleTo(Json::stringValue) &&
								!event_reason.isNull() && event_reason.isConvertibleTo(Json::stringValue))
							{
								bool is_allowed = m_event_filter->allows_all();
								std::string type = kind.asString();
								if(!is_allowed && !type.empty())
								{
									std::string reason = event_reason.asString();
									is_allowed = m_event_filter->allows_all(type);
									if(!is_allowed && !reason.empty())
									{
										is_allowed = m_event_filter->has(type, reason);
									}
								}
								if(is_allowed)
								{
									g_logger.log("K8s EVENT: adding event.", sinsp_logger::SEV_TRACE);
									k8s_event_t& evt = m_state->add_component<k8s_events, k8s_event_t>(m_state->get_events(),
																data->m_name, data->m_uid, data->m_namespace);
									m_state->update_event(evt, json);
								}
								else
								{
									g_logger.log("K8s EVENT: filter does not allow {\"" + type + "\", \"{" + event_reason.asString() + "\"} }", sinsp_logger::SEV_TRACE);
									g_logger.log(m_event_filter->to_string(), sinsp_logger::SEV_TRACE);
									return false;
								}
							}
							else
							{
								g_logger.log("K8s EVENT: event type or involvedObject kind not found.", sinsp_logger::SEV_ERROR);
								g_logger.log(Json::FastWriter().write(json), sinsp_logger::SEV_TRACE);
								return false;
							}
						}
						else
						{
							g_logger.log("K8s EVENT: old event, ignoring: "
										 ", lastTimestamp=" + std::to_string(last_ts) + ", now_ts=" + std::to_string(now_ts),
										sinsp_logger::SEV_DEBUG);
							return true;
						}
					}
					else
					{
						g_logger.log("K8s EVENT: involvedObject not found.", sinsp_logger::SEV_ERROR);
						g_logger.log(Json::FastWriter().write(json), sinsp_logger::SEV_TRACE);
						return false;
					}
				}
				else
				{
					g_logger.log(std::string("Unsupported K8S Event reason: ") +
								 std::to_string(data->m_reason), sinsp_logger::SEV_ERROR);
					return false;
				}
			}
			else
			{
				g_logger.log("K8s EVENT: msg data is null.", sinsp_logger::SEV_ERROR);
				g_logger.log(Json::FastWriter().write(json), sinsp_logger::SEV_TRACE);
				return false;
			}
		}
		else
		{
			g_logger.log("K8s EVENT: state is null.", sinsp_logger::SEV_ERROR);
			return false;
		}
	}
	else
	{
		g_logger.log("K8s EVENT: no filter, K8s events disabled.", sinsp_logger::SEV_TRACE);
		return false;
	}
	return true;
}
