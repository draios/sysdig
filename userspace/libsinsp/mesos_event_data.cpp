//
// mesos_event_data.cpp
//


#include "mesos_event_data.h"

mesos_event_data::event_map_t mesos_event_data::m_events =
{
	{ MESOS_UNKNOWN_EVENT,              "unknown_event"        },
	{ MESOS_API_POST_EVENT,             "api_post_event"       },
	{ MESOS_STATUS_UPDATE_EVENT,        "status_update_event"  },
	{ MESOS_APP_TERMINATED_EVENT,       "app_terminated_event" },
	{ MESOS_DEPLOYMENT_SUCCESS_EVENT,   "deployment_success"   },
	{ MESOS_GROUP_CHANGE_SUCCESS_EVENT, "group_change_success" },
	{ MESOS_IGNORED_EVENT,              "ignored_event"        }
};

mesos_event_data::mesos_event_data(const std::string& data): m_event(MESOS_UNKNOWN_EVENT)
{
	std::string event_type = get_event_type(data);

	if(!event_type.empty())
	{
		m_event = get_event_type_from_name(event_type);

		std::string name = "data:";
		std::string::size_type pos = data.find(name);
		if(pos != std::string::npos)
		{
			pos += name.size();
			std::string val = data.substr(pos);
			m_data = trim(val);
			//g_logger.log("Mesos event data:" + m_data, sinsp_logger::SEV_DEBUG);
		}
		else
		{
			throw sinsp_exception("Invalid event data.");
		}
	}
	else
	{
		g_logger.log("Event data object created for ignored event: " + event_type, sinsp_logger::SEV_WARNING);
	}
}

mesos_event_data::mesos_event_data(const mesos_event_data& other):
	m_event(other.m_event),
	m_data(other.m_data)
{
}

mesos_event_data::mesos_event_data(mesos_event_data&& other):
	m_event(std::move(other.m_event)),
	m_data(std::move(other.m_data))
{
}

mesos_event_data& mesos_event_data::operator=(mesos_event_data&& other)
{
	if(this != &other)
	{
		m_event = other.m_event;
		m_data = other.m_data;
	}
	return *this;
}

mesos_event_data::type mesos_event_data::get_event_type_from_name(const std::string& name)
{
	if(!name.empty())
	{
		for(const auto& evt : m_events)
		{
			if(name == evt.second)
			{
				return evt.first;
			}
		}
		return MESOS_IGNORED_EVENT;
	}
	return MESOS_UNKNOWN_EVENT;
}

std::string mesos_event_data::get_event_type(const std::string& data)
{
	std::string event_type;
	std::string name = "event:";
	std::string::size_type pos = data.find(name);
	std::string::size_type end = data.find('\n', pos);
	if(pos != std::string::npos && end != std::string::npos)
	{
		pos += name.size();
		if(end - pos > 0)
		{
			event_type = data.substr(pos, end - pos);
			trim(event_type);
			for(const auto& evt : m_events)
			{
				if(event_type == evt.second)
				{
					return event_type;
				}
			}
			return m_events[MESOS_IGNORED_EVENT];
		}
	}
	return m_events[MESOS_UNKNOWN_EVENT];
}

mesos_event_data::type mesos_event_data::get_event_type(const Json::Value& root)
{
	Json::Value ev_type = root["eventType"];
	if(!ev_type.isNull() && ev_type.isString())
	{
		for(const auto& evt : m_events)
		{
			if(evt.second == ev_type.asString())
			{
				return evt.first;
			}
		}
		return MESOS_IGNORED_EVENT;
	}

	return MESOS_UNKNOWN_EVENT;
}

