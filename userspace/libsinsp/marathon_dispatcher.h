//
// marathon_dispatcher.h
//
// kubernetes REST API notification abstraction
//

#pragma once

#include "mesos_common.h"
#include "mesos_state.h"
#include "mesos_event_data.h"
#include "json/json.h"
#include <deque>
#include <string>

class marathon_dispatcher
{
public:
	typedef std::shared_ptr<marathon_dispatcher> ptr_t;

	struct msg_data
	{
		mesos_event_data::type  m_type = mesos_event_data::MESOS_UNKNOWN_EVENT;
		std::string             m_status;

		bool is_valid() const
		{
			return m_type != mesos_event_data::MESOS_UNKNOWN_EVENT;
		}
	};

	marathon_dispatcher() = delete;

	marathon_dispatcher(mesos_state_t& state, const std::string& framework_id);

	void enqueue(mesos_event_data&& data);

	void extract_data(const std::string& json);

	const std::string& get_id() const;

private:
	const std::string& next_msg();
	void remove();
	void dispatch();
	void handle_api_post(const Json::Value& root);
	void handle_status_update(const Json::Value& root);
	void handle_app_terminate(const Json::Value& root);
	void handle_group_change(const Json::Value& root);
	void handle_deployment_success(const Json::Value& root);

	typedef std::deque<std::string> list;

	list           m_messages;
	mesos_state_t& m_state;
	std::string    m_framework_id;
};


inline const std::string& marathon_dispatcher::next_msg()
{
	return m_messages.front();
}

inline void marathon_dispatcher::remove()
{
	m_messages.pop_front();
}

inline const std::string& marathon_dispatcher::get_id() const
{
	return m_framework_id;
}

