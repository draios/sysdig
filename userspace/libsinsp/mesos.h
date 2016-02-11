//
// mesos.h
//
#ifndef _WIN32
#pragma once

#include "json/json.h"
#include "mesos_common.h"
#include "mesos_component.h"
#include "mesos_http.h"
#include "marathon_http.h"
#include "mesos_state.h"
#include "mesos_collector.h"
#include "uri.h"
#include <sstream>
#include <utility>
#include <unordered_map>

class mesos
{
public:
	static const std::string default_state_uri;
	static const std::string default_state_api;
	static const std::string default_marathon_uri;
	static const std::string default_groups_api;
	static const std::string default_apps_api;
	static const std::string default_watch_api;

	typedef mesos_http::marathon_uri_t/*std::vector<std::string>*/ uri_list_t;

	mesos(const std::string& state_uri = default_state_uri,
		const std::string& state_api = default_state_api,
		const uri_list_t& marathon_uris = uri_list_t(),
		const std::string& groups_api = "",
		const std::string& apps_api = "",
		bool discover_mesos_leader = false);

	~mesos();

	const mesos_state_t& get_state() const;
	bool is_alive() const;
	void refresh();
	void clear_mesos();

	bool has_marathon() const;
	void clear_marathon();

#ifdef HAS_CAPTURE
	void send_data_request(bool collect = true);
	void collect_data();
#endif // HAS_CAPTURE

private:
#ifdef HAS_CAPTURE
	void init();
	void send_mesos_data_request();
	void connect_mesos();
	void check_collector_status(int expected);
	void send_marathon_data_request();
	void connect_marathon();

	template <typename T>
	bool connect(T http, typename T::element_type::callback_func_t func, int expected_connections)
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
				http->set_parse_func(func);
				m_collector.add(http);
			}
			check_collector_status(expected_connections);
			return m_collector.has(http);
		}
		return false;
	}
#endif // HAS_CAPTURE

	void rebuild_mesos_state(bool full = false);
	void rebuild_marathon_state(bool full = false);

	void handle_frameworks(const Json::Value& root);
	void add_framework(const Json::Value& framework);
	void add_tasks(mesos_framework& framework, const Json::Value& f_val);
	void add_tasks_impl(mesos_framework& framework, const Json::Value& tasks);
	void handle_slaves(const Json::Value& root);
	void add_slave(const Json::Value& framework);

	void check_frameworks(const std::string& json);
	void set_state_json(std::string&& json, const std::string&);
	void parse_state(std::string&& json, const std::string&);
	void set_marathon_groups_json(std::string&& json, const std::string& framework_id);
	void parse_groups(std::string&& json, const std::string& framework_id);
	void set_marathon_apps_json(std::string&& json, const std::string& framework_id);
	void parse_apps(std::string&& json, const std::string& framework_id);

#ifdef HAS_CAPTURE
	void remove_framework(const Json::Value& framework);

	typedef std::unordered_map<std::string, marathon_http::ptr_t>       marathon_http_map;

	mesos_http::ptr_t m_state_http;
	marathon_http_map m_marathon_groups_http;
	marathon_http_map m_marathon_apps_http;
	mesos_collector   m_collector;
	std::string       m_mesos_uri;
	uri_list_t        m_marathon_uris;
#endif // HAS_CAPTURE

	mesos_state_t     m_state;
	bool              m_creation_logged;
	bool              m_discover_mesos_leader;
	bool              m_discover_marathon;

	typedef std::map<std::string, std::string> json_map_type_t;
	std::string m_mesos_state_json;
	json_map_type_t m_marathon_groups_json;
	json_map_type_t m_marathon_apps_json;
	time_t m_last_mesos_refresh = 0;
	time_t m_last_marathon_refresh = 0;

	typedef std::unordered_set<std::string> framework_list_t;
	framework_list_t m_inactive_frameworks;
	framework_list_t m_activated_frameworks;

	static const mesos_component::component_map m_components;

	friend class mesos_http;
	friend class marathon_http;
};

inline const mesos_state_t& mesos::get_state() const
{
	return m_state;
}

#ifdef HAS_CAPTURE
inline bool mesos::has_marathon() const
{
	return m_marathon_groups_http.size() || m_marathon_apps_http.size();
}
#endif // HAS_CAPTURE

inline void mesos::clear_mesos()
{
	m_state.clear_mesos();
}

inline void mesos::clear_marathon()
{
	m_state.clear_marathon();
}

inline void mesos::parse_apps(std::string&& json, const std::string& framework_id)
{
	m_state.parse_apps(std::move(json), framework_id);
}

inline void mesos::parse_groups(std::string&& json, const std::string& framework_id)
{
	m_state.parse_groups(std::move(json), framework_id);
}

#endif // _WIN32
