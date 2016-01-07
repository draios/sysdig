//
// mesos_event_data.h
//
// connects and gets the data from mesos_net REST API interface
//
#pragma once

#include "mesos_component.h"


class mesos_event_data
{
public:
	enum type
	{
		MESOS_UNKNOWN_EVENT,
		MESOS_API_POST_EVENT,
		MESOS_STATUS_UPDATE_EVENT,
		MESOS_APP_TERMINATED_EVENT,
		MESOS_GROUP_CHANGE_SUCCESS_EVENT,
		MESOS_DEPLOYMENT_SUCCESS_EVENT,
		MESOS_IGNORED_EVENT
	};

	typedef std::map<type, std::string> event_map_t;
	static event_map_t m_events;

	mesos_event_data() = delete;

	mesos_event_data(const std::string& data);

	mesos_event_data(const mesos_event_data& other);

	mesos_event_data(mesos_event_data&& other);

	mesos_event_data& operator=(mesos_event_data&& other);

	type get_event() const;

	const std::string& get_data() const;
	std::string& get_data();
	void set_data(const std::string&& data);

	static std::string get_event_type(const std::string& data);
	static type get_event_type_from_name(const std::string& name);
	static type get_event_type(const Json::Value& root);

	static bool is_ignored(const std::string& evt);

private:
	type        m_event;
	std::string m_data;
};

inline mesos_event_data::type mesos_event_data::get_event() const
{
	return m_event;
}

inline const std::string& mesos_event_data::get_data() const
{
	return m_data;
}

inline std::string& mesos_event_data::get_data()
{
	return m_data;
}

inline bool mesos_event_data::is_ignored(const std::string& evt)
{
	return evt == m_events[MESOS_IGNORED_EVENT];
}

