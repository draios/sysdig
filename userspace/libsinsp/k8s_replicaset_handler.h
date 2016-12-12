//
// k8s_replicaset_handler.h
//

#pragma once

#include "json/json.h"
#include "sinsp_auth.h"
#include "k8s_handler.h"
#include "k8s_state.h"

class sinsp;

class k8s_replicaset_handler : public k8s_handler
{
public:
	k8s_replicaset_handler(k8s_state_t& state
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

	~k8s_replicaset_handler();

private:
	static std::string EVENT_FILTER;
	static std::string STATE_FILTER;

	virtual bool handle_component(const Json::Value& json, const msg_data* data = 0);
};
