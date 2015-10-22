//
// k8s_net.cpp
//

#include "k8s_net.h"
#include "k8s_component.h"
#include "k8s.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include <sstream>
#include <utility>
#include <memory>


k8s_net::k8s_net(k8s& kube, const std::string& uri, const std::string& api) : m_k8s(kube),
		m_uri(uri + api),
		m_stopped(true),
		m_poller(kube.watch_in_thread())
#ifndef K8S_DISABLE_THREAD
		,m_thread(0)
#endif
{
	init();
}

k8s_net::~k8s_net()
{
#ifndef K8S_DISABLE_THREAD
	delete m_thread;
#endif

	for (auto& component : k8s_component::list)
	{
		delete m_api_interfaces[component.first];
	}
}

void k8s_net::init()
{
	std::string uri = m_uri.to_string();
	std::string::size_type endpos = uri.find_first_of('@');
	if(endpos != std::string::npos)
	{
		std::string::size_type beginpos = uri.find("://") + 3;
		if(beginpos != std::string::npos)
		{
			m_creds = uri.substr(beginpos, endpos - beginpos);
		}
		else
		{
			throw sinsp_exception("Bad URI");
		}
	}

	for (auto& component : k8s_component::list)
	{
		m_api_interfaces[component.first] = 0;
	}
}

void k8s_net::watch()
{
	bool in_thread = m_k8s.watch_in_thread();
#ifdef K8S_DISABLE_THREAD
	if(in_thread)
	{
		g_logger.log("Thread run requested for non-thread binary.", sinsp_logger::SEV_WARNING);
	}
#else
	if(m_stopped && in_thread)
	{
		subscribe();
		m_stopped = false;
		m_thread = new std::thread(&k8s_poller::poll, &m_poller);
	}
	else
#endif // K8S_DISABLE_THREAD
	if(!in_thread)
	{
		if(!m_poller.subscription_count())
		{
			subscribe();
		}
		m_poller.poll();
	}
}
	
void k8s_net::subscribe()
{
	for (auto& api : m_api_interfaces)
	{
		m_poller.add(api.second);
	}
}

void k8s_net::unsubscribe()
{
	m_poller.stop();
	m_poller.remove_all();
}

void k8s_net::stop_watching()
{
	if(!m_stopped)
	{
		m_stopped = true;
		unsubscribe();
#ifndef K8S_DISABLE_THREAD
		if(m_thread)
		{
			m_thread->join();
		}
#endif
	}
}

void k8s_net::get_all_data(const k8s_component::component_map::value_type& component, std::ostream& out)
{
	if(m_api_interfaces[component.first] == 0)
	{
		std::string protocol = m_uri.get_scheme();
		std::ostringstream os;
		os << m_uri.get_host();
		int port = m_uri.get_port();
		if (port)
		{
			os << ':' << port;
		}
		m_api_interfaces[component.first] = new k8s_http(m_k8s, component.second, os.str(), protocol, m_creds);
	}
	
	if(!m_api_interfaces[component.first]->get_all_data(out))
	{
		throw sinsp_exception(std::string("An error occured while trying to retrieve data for k8s ") + component.second);
	}
}

