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

using Poco::URI;

k8s_net::k8s_net(k8s& kube, const std::string& uri, const std::string& api) : m_k8s(kube),
		m_uri(uri + api),
		m_stopped(true)
{
	init();
}

k8s_net::~k8s_net()
{
	for (auto& component : k8s_component::list)
	{
		delete m_api_interfaces[component.first];
	}
}

void k8s_net::init()
{
	m_uri.normalize();

	std::string uri = m_uri.toString();
	std::string::size_type endpos = uri.find_first_of('@');
	if (endpos != std::string::npos)
	{
		std::string::size_type beginpos = uri.find("://") + 3;
		if (beginpos != std::string::npos)
		{
			m_creds = uri.substr(beginpos, endpos - beginpos);
		}
		else
		{
			throw std::invalid_argument("Bad URI");
		}
	}

	for (auto& component : k8s_component::list)
	{
		m_api_interfaces[component.first] = 0;
	}
}

void k8s_net::start_watching()
{
	if (m_stopped)
	{
		subscribe();
		m_stopped = false;
		m_thread = std::move(std::thread(&k8s_poller::poll, &m_poller));
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
	if (!m_stopped)
	{
		m_stopped = true;
		unsubscribe();
		m_thread.join();
	}
}

void k8s_net::get_all_data(const k8s_component::component_map::value_type& component, std::ostream& out)
{
	if (m_api_interfaces[component.first] == 0)
	{
		std::string protocol = m_uri.getScheme();
		std::ostringstream os;
		os << m_uri.getHost() << ':' << m_uri.getPort();
		m_api_interfaces[component.first] = new k8s_http(m_k8s, component.second, os.str(), protocol, m_creds);
	}
	
	m_api_interfaces[component.first]->get_all_data(out);
}

