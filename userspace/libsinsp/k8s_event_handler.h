//
// k8s_event_handler.h
//

#pragma once

#include "json/json.h"
#include "sinsp_auth.h"
#include "k8s_handler.h"
#include "k8s_event_data.h"

class sinsp;

class k8s_event_handler : public k8s_handler
{
public:
	typedef user_event_filter_t::ptr_t filter_ptr_t;

	k8s_event_handler(k8s_state_t& state
#ifdef HAS_CAPTURE
		,ptr_t dependency_handler
		,collector_ptr_t collector = nullptr
		,std::string url = ""
		,const std::string& http_version = "1.1"
		,ssl_ptr_t ssl = 0
		,bt_ptr_t bt = 0
		,bool connect = true
		,bool blocking_socket = false
#endif // HAS_CAPTURE
		,filter_ptr_t event_filter = 0);

	~k8s_event_handler();

private:
	static std::string EVENT_FILTER;
	static std::string STATE_FILTER;

	bool handle_component(const Json::Value& json, const msg_data* data = 0);
	void handle_json(Json::Value&& root);

	filter_ptr_t m_event_filter;
	bool         m_event_ignored = false;
	bool         m_event_limit_exceeded = false;
};
