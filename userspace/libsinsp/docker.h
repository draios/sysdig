//
// docker.h
//

#if defined(__linux__)

#pragma once

#include "json/json.h"
#include "socket_collector.h"
#include "uri.h"
#include "user_event.h"
#include <sstream>
#include <utility>
#include <unordered_map>

class docker
{
public:
	typedef std::vector<std::string> uri_list_t;
	typedef std::shared_ptr<Json::Value> json_ptr_t;
	typedef std::set<std::string, ci_compare> event_filter_t;
	typedef user_event_filter_t::ptr_t event_filter_ptr_t;

	static const int default_timeout_ms = 1000L;

	docker(std::string url = "",
		const std::string& path = "/events",
		const std::string& http_version = "1.0",
		int timeout_ms = default_timeout_ms,
		bool is_captured = false,
		bool verbose = false,
		event_filter_ptr_t event_filter = nullptr);

	~docker();

	bool is_alive() const;
	void set_event_json(json_ptr_t json, const std::string&);
	void simulate_event(const std::string& json);
	const std::string& get_id() const;
	void reset_event_counter();

#ifdef HAS_CAPTURE
	void send_data_request(bool collect = true);
	void collect_data();
	void set_event_filter(event_filter_ptr_t event_filter);
	void set_machine_id(const std::string& machine_id);
	const std::string& get_machine_id() const;

	static std::string get_socket_file();

private:
	static const std::string DOCKER_SOCKET_FILE;
	void connect();
	void send_event_data_request();
	void check_collector_status();

	void handle_event(Json::Value&& root);

	template <typename T>
	bool connect(T http, typename T::element_type::json_callback_func_t func, int expected_connections)
	{
		if(http)
		{
			if(m_collector.has(http))
			{
				if(!http->is_connected())
				{
					m_collector.remove(http);
				}
			}
			if(!m_collector.has(http))
			{
				http->set_json_callback(func);
				m_collector.add(http);
			}
			check_collector_status();
			return m_collector.has(http);
		}
		return false;
	}

	bool is_container_event(const std::string& evt_name);
	bool is_image_event(const std::string& evt_name);
	bool is_volume_event(const std::string& evt_name);
	bool is_network_event(const std::string& evt_name);

	typedef socket_data_handler<docker> handler_t;
	typedef handler_t::ptr_t            handler_ptr_t;
	typedef socket_collector<handler_t> collector_t;

	std::string   m_id;
	handler_ptr_t m_event_http;
	collector_t   m_collector;
	std::string   m_event_uri;
#endif // HAS_CAPTURE

private:

	typedef std::vector<json_ptr_t> event_list_t;
	typedef sinsp_logger::event_severity severity_t;
	typedef std::unordered_map<std::string, severity_t> severity_map_t;
	typedef std::unordered_map<std::string, std::string> name_translation_map_t;
	typedef std::set<std::string> entity_events_t;
	const std::string& translate_name(const std::string& event_name);

	long                   m_timeout_ms;
	bool                   m_is_captured;
	bool                   m_verbose;
	event_filter_ptr_t     m_event_filter;
	std::string            m_machine_id;
	event_list_t           m_events;
	const entity_events_t  m_container_events;
	const entity_events_t  m_image_events;
	const entity_events_t  m_volume_events;
	const entity_events_t  m_network_events;
	severity_map_t         m_severity_map;
	name_translation_map_t m_name_translation;
	size_t                 m_event_counter = 0;
	bool                   m_event_limit_exceeded = false;
};

inline const std::string& docker::get_id() const
{
	return m_id;
}

inline void docker::set_event_filter(event_filter_ptr_t event_filter)
{
	m_event_filter = event_filter;
}

inline void docker::set_machine_id(const std::string& machine_id)
{
	m_machine_id = machine_id;
}

inline const std::string& docker::get_machine_id() const
{
	return m_machine_id;
}

inline const std::string& docker::translate_name(const std::string& event_name)
{
	const auto& it = m_name_translation.find(event_name);
	if(it != m_name_translation.end())
	{
		return it->second;
	}
	return event_name;
}

inline bool docker::is_container_event(const std::string& evt_name)
{
	return m_container_events.find(evt_name) != m_container_events.end();
}

inline bool docker::is_image_event(const std::string& evt_name)
{
	return m_image_events.find(evt_name) != m_image_events.end();
}

inline bool docker::is_volume_event(const std::string& evt_name)
{
	return m_volume_events.find(evt_name) != m_volume_events.end();
}

inline bool docker::is_network_event(const std::string& evt_name)
{
	return m_network_events.find(evt_name) != m_network_events.end();
}

inline void docker::reset_event_counter()
{
	m_event_counter = 0;
}

#endif // __linux__
