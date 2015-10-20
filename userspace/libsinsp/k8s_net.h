//
// k8s_net.h
//
// connects and gets the data from k8s_net REST API interface
//
#pragma once

#include "k8s_component.h"
#include "k8s_event_data.h"
#include "k8s_http.h"
#include "k8s_poller.h"
#include "uri.h"
#include <thread>
#include <sstream>
#include <utility>

class k8s;

class k8s_net
{
public:
	k8s_net(k8s& kube, const std::string& uri = "http://localhost:80",
		const std::string& api = "/api/v1/");

	~k8s_net();

	void get_all_data(const k8s_component::component_map::value_type& component, std::ostream& out);

	void start_watching();
	
	void stop_watching();

	bool is_watching() const;

private:
	void subscribe();
	
	void unsubscribe();

	void dispatch_events();

	void init();

	bool is_secure();

	typedef std::map<k8s_component::type, k8s_http*> api_map_t;

	k8s&        m_k8s;
	uri         m_uri;
	std::string m_creds;
	std::thread m_thread;
	bool        m_stopped;
	api_map_t   m_api_interfaces;
	k8s_poller  m_poller;
};

inline bool k8s_net::is_secure()
{
	return m_uri.get_scheme() == "https";
}

inline bool k8s_net::is_watching() const
{
	return !m_stopped;
}


