//
// k8s_net.h
//
// connects and gets the data from k8s_net REST API interface
//
#pragma once

#include "k8s_component.h"
#include "k8s_event_data.h"
#include "k8s_http.h"
#include "k8s_collector.h"
#include "uri.h"
#include <sstream>
#include <utility>
#ifndef K8S_DISABLE_THREAD
#include <thread>
#endif

class k8s;

class k8s_net
{
public:
	k8s_net(k8s& kube, const std::string& uri = "http://localhost:80",
		const std::string& api = "/api/v1/");

	~k8s_net();

	void get_all_data(const k8s_component::component_map::value_type& component, std::ostream& out);

	void watch();

	void stop_watching();

	bool is_watching() const;

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
	bool          m_stopped;
	api_map_t     m_api_interfaces;
	k8s_collector m_collector;
#ifndef K8S_DISABLE_THREAD
	std::thread* m_thread;
#endif
};

inline bool k8s_net::is_secure()
{
	return m_uri.get_scheme() == "https";
}

inline bool k8s_net::is_watching() const
{
	return !m_stopped;
}

inline bool k8s_net::is_healthy() const
{
	return m_collector.subscription_count() ==
		static_cast<int>(m_api_interfaces.size());
}


