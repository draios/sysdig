//
// k8s_dispatcher.h
//
// kubernetes REST API notification abstraction
//

#pragma once

#include "k8s_common.h"
#include "k8s.h"
#include "k8s_component.h"
#include "k8s_state.h"
#include "k8s_event_data.h"
#include "json/json.h"
#include <deque>
#include <string>

class k8s_dispatcher
{
public:
	typedef user_event_filter_t::ptr_t filter_ptr_t;

	enum msg_reason
	{
		COMPONENT_ADDED,
		COMPONENT_MODIFIED,
		COMPONENT_DELETED,
		COMPONENT_ERROR,
		COMPONENT_UNKNOWN // only to mark bad event messages
	};

	struct msg_data
	{
		msg_reason  m_reason = COMPONENT_UNKNOWN;
		std::string m_name;
		std::string m_uid;
		std::string m_namespace;

		bool is_valid() const
		{
			return m_reason != COMPONENT_UNKNOWN;
		}
	};

	k8s_dispatcher() = delete;

	k8s_dispatcher(k8s_component::type t,
		k8s_state_t& state,
		filter_ptr_t event_filter = nullptr);

	void enqueue(k8s_event_data&& data);

	void extract_data(const std::string& json, bool enqueue = false);

private:
	const std::string& next_msg();
	
	msg_data get_msg_data(Json::Value& root);

	bool is_valid(const std::string& msg);

	bool is_ready(const std::string& msg);

	void remove();

	void dispatch();

	void handle_node(const Json::Value& root, const msg_data& data);
	void handle_namespace(const Json::Value& root, const msg_data& data);
	void handle_pod(const Json::Value& root, const msg_data& data);
	void handle_rc(const Json::Value& root, const msg_data& data);
	void handle_service(const Json::Value& root, const msg_data& data);
	void handle_event(const Json::Value& root, const msg_data& data);

	// clears the content of labels and fills it with new values, if any
	template <typename T>
	void handle_labels(T& component, const Json::Value& metadata, const std::string& name)
	{
		if(!metadata.isNull())
		{
			k8s_pair_list entries = k8s_component::extract_object(metadata, name);
			component.set_labels(std::move(entries));
		}
		else
		{
			g_logger.log("Null metadata object received", sinsp_logger::SEV_ERROR);
		}
	}

	// clears the content of selectors and fills it with new values, if any
	template <typename T>
	void handle_selectors(T& component, const Json::Value& spec, const std::string& name)
	{
		if(!spec.isNull())
		{
			k8s_pair_list selectors = k8s_component::extract_object(spec, name);
			component.set_selectors(std::move(selectors));
		}
		else
		{
			g_logger.log("Null spec object received", sinsp_logger::SEV_ERROR);
		}
	}

	void log_error(const Json::Value& root, const std::string& comp);

	static std::string to_reason_desc(msg_reason reason);

	static msg_reason to_reason(const std::string& desc);

	typedef std::deque<std::string> list;

	k8s_component::type m_type;
	list                m_messages;
	k8s_state_t&        m_state;
	filter_ptr_t        m_event_filter;
	std::string         m_machine_id;
};


inline const std::string& k8s_dispatcher::next_msg()
{
	return m_messages.front();
}

inline void k8s_dispatcher::remove()
{
	m_messages.pop_front();
}