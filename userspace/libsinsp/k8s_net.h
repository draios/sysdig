//
// k8s_net.h
//
// connects and gets the data from k8s_net REST API interface
//
#pragma once

#ifdef HAS_CAPTURE

#include "k8s_component.h"
#include "k8s_event_data.h"
#include "k8s_handler.h"
#include "k8s_event_data.h"
#include "uri.h"
#include "sinsp_curl.h"
#include <sstream>
#include <utility>

class k8s;

class k8s_net
{
public:
	typedef sinsp_ssl::ptr_t              ssl_ptr_t;
	typedef sinsp_bearer_token::ptr_t     bt_ptr_t;
	typedef k8s_component::ext_list_ptr_t ext_list_ptr_t;
	typedef user_event_filter_t::ptr_t    filter_ptr_t;
	typedef k8s_handler::ptr_t            handler_ptr_t;
	typedef k8s_handler::collector_t      collector_t;
	typedef k8s_handler::collector_ptr_t  collector_ptr_t;

	k8s_net(k8s& kube, k8s_state_t& state, const std::string& uri = "http://localhost:80",
		ssl_ptr_t ssl = nullptr,
		bt_ptr_t bt = nullptr,
		ext_list_ptr_t extensions = nullptr,
		filter_ptr_t event_filter = nullptr);

	~k8s_net();

	static handler_ptr_t get_handler(k8s_state_t& state, const k8s_component::type component, bool connect = true,
									 collector_ptr_t collector = nullptr, const std::string& urlstr = "",
									 ssl_ptr_t ssl = nullptr, bt_ptr_t bt = nullptr,
									 filter_ptr_t event_filter = nullptr);
	void add_handler(const k8s_component::type_map::value_type& component);
	bool has_handler(const k8s_component::type_map::value_type& component);
	handler_ptr_t get_handler(const k8s_component::type_map::value_type& component);
	bool has_dependency(const k8s_component::type_map::value_type& component);

	bool is_state_built(const k8s_component::type_map::value_type& component)
	{
		const auto& it = m_handlers.find(component.first);
		if(it != m_handlers.end())
		{
			return it->second && it->second->is_state_built();
		}
		return false;
	}

	void watch();
	void stop_watching();
	bool is_healthy() const;

private:
	void init();
	bool is_secure();
	void cleanup();

	typedef k8s_handler::handler_t                       handler_t;
	typedef std::map<k8s_component::type, handler_ptr_t> handler_map_t;

	k8s&            m_k8s;
	k8s_state_t&    m_state;
	collector_ptr_t m_collector;
	uri             m_uri;
	ssl_ptr_t       m_ssl;
	bt_ptr_t        m_bt;
	bool            m_stopped;
	handler_map_t   m_handlers;
	ext_list_ptr_t  m_extensions;
	filter_ptr_t    m_event_filter;
};

inline bool k8s_net::is_secure()
{
	return m_uri.get_scheme() == "https";
}

inline bool k8s_net::is_healthy() const
{
	return m_collector->subscription_count() ==
		static_cast<int>(m_handlers.size());
}

inline bool k8s_net::has_handler(const k8s_component::type_map::value_type& component)
{
	auto it = m_handlers.find(component.first);
	return (it != m_handlers.end()) && it->second;
}

inline k8s_net::handler_ptr_t k8s_net::get_handler(const k8s_component::type_map::value_type& component)
{
	auto it = m_handlers.find(component.first);
	if(it != m_handlers.end())
	{
		return it->second;
	}
	return nullptr;
}

#endif // HAS_CAPTURE
