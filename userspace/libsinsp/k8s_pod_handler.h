//
// k8s_pod_handler.h
//

#pragma once

#include "json/json.h"
#include "sinsp_auth.h"
#include "k8s_handler.h"
#include "k8s_component.h"

class sinsp;

class k8s_pod_handler : public k8s_handler
{
public:
	k8s_pod_handler(k8s_state_t& state
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
		);

	~k8s_pod_handler();

	static bool is_pod_active(const Json::Value& item);
	static std::vector<std::string> extract_pod_container_ids(const Json::Value& item);
	static k8s_container::list extract_pod_containers(const Json::Value& item);
	static void extract_pod_data(const Json::Value& item, k8s_pod_t& pod);
	static size_t extract_pod_restart_count(const Json::Value& item);

private:
	static std::string EVENT_FILTER;
	static std::string STATE_FILTER;

	virtual bool handle_component(const Json::Value& json, const msg_data* data = 0);
};
