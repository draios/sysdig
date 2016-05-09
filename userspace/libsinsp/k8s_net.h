//
// k8s_net.h
//
// connects and gets the data from k8s_net REST API interface
//
#pragma once

#ifdef HAS_CAPTURE

#include "k8s_component.h"
#include "k8s_event_data.h"
#include "k8s_http.h"
#include "k8s_collector.h"
#include "uri.h"
#include "sinsp_curl.h"
#include <sstream>
#include <utility>

class k8s;

class k8s_net
{
public:
	typedef sinsp_curl::ssl::ptr_t          ssl_ptr_t;
	typedef sinsp_curl::bearer_token::ptr_t bt_ptr_t;

	k8s_net(k8s& kube, const std::string& uri = "http://localhost:80",
		const std::string& api = "/api/v1/",
		ssl_ptr_t ssl = 0,
		bt_ptr_t bt = 0,
		bool curl_debug = false);

	~k8s_net();

	void get_all_data(const k8s_component::type_map::value_type& component, std::ostream& out);

	void add_api_interface(const k8s_component::type_map::value_type& component);

	void watch();

	void stop_watching();

	bool is_healthy() const;

private:
	void subscribe();

	void unsubscribe();

	void dispatch_events();

	void init();

	void end_thread();

	bool is_secure();

	void cleanup();

	typedef std::map<k8s_component::type, k8s_http*> api_map_t;

	k8s&          m_k8s;
	uri           m_uri;
	std::string   m_creds;
	std::string   m_api;
	ssl_ptr_t     m_ssl;
	bt_ptr_t      m_bt;
	bool          m_stopped;
	api_map_t     m_api_interfaces;
	k8s_collector m_collector;
#ifndef K8S_DISABLE_THREAD
	std::thread* m_thread;
#endif
	bool          m_curl_debug;
};

inline bool k8s_net::is_secure()
{
	return m_uri.get_scheme() == "https";
}

inline bool k8s_net::is_healthy() const
{
	return m_collector.subscription_count() ==
		static_cast<int>(m_api_interfaces.size());
}

#endif // HAS_CAPTURE

