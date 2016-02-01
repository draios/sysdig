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
#include "mesos_event_data.h"
#include "marathon_dispatcher.h"
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

	typedef std::vector<std::string> uri_list_t;

	mesos(const std::string& state_uri = default_state_uri,
		const std::string& state_api = default_state_api,
		const uri_list_t& marathon_uris = uri_list_t(),
		const std::string& groups_api = "",
		const std::string& apps_api = "",
		const std::string& watch_api = "");

	~mesos();

	const mesos_state_t& get_state() const;
	bool is_alive() const;
	void refresh();
	void clear_mesos();

	bool has_marathon() const;
	void watch_marathon();
	void clear_marathon();

	void send_data_request(bool collect = true)
	{
		connect_mesos();
		send_mesos_data_request();
		if(has_marathon())
		{
			connect_marathon();
			send_marathon_data_request();
		}
		if(!m_mesos_state_json.empty()) { return; }
		for(auto& group : m_marathon_groups_json)
		{
			if(!group.second.empty()) { return; }
		}
		for(auto& app : m_marathon_apps_json)
		{
			if(!app.second.empty()) { return; }
		}
		if(collect) { collect_data(); }
	}

	void collect_data()
	{
		 m_collector.get_data();
		 if(!m_mesos_state_json.empty())
		 {
			if(!m_marathon_apps_json.empty() && !m_marathon_groups_json.empty())
			{
				for(auto& group : m_marathon_groups_json)
				{
					if(group.second.size())
					{
						json_map_type_t::iterator app_it = m_marathon_apps_json.find(group.first);
						if(app_it != m_marathon_apps_json.end())
						{
							if(!app_it->second.empty())
							{
								if(!m_mesos_state_json.empty())
								{
									parse_state(std::move(m_mesos_state_json), "");
									m_mesos_state_json.clear();
								}
								// +++ order is important - apps belong to groups and must be processed after
								parse_groups(std::move(group.second), group.first);
								parse_apps(std::move(app_it->second), app_it->first);
								// ---
								group.second.clear();
								app_it->second.clear();
							}
						}
						else
						{
							// must never happen
							throw sinsp_exception("A discrepancy found between groups and apps "
												  "(app json for framework [" + group.first + "] not found in json map).");
						}
					}
				}
			}
		 }
	}

private:
	void send_mesos_data_request();
	void connect_mesos();
	void send_marathon_data_request();
	void connect_marathon();

	template <typename T>
	void connect(T http, typename T::element_type::callback_func_t func)
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
	}

	void rebuild_mesos_state(bool full = false);
	void rebuild_marathon_state(bool full = false);

	void handle_frameworks(const Json::Value& root);
	void add_framework(const Json::Value& framework);
	void add_tasks(mesos_framework& framework, const Json::Value& f_val);
	void add_tasks_impl(mesos_framework& framework, const Json::Value& tasks);
	void handle_slaves(const Json::Value& root);
	void add_slave(const Json::Value& framework);

	void set_state_json(std::string&& json, const std::string&);
	void parse_state(std::string&& json, const std::string&);
	void set_marathon_groups_json(std::string&& json, const std::string& framework_id);
	void parse_groups(std::string&& json, const std::string& framework_id);
	void set_marathon_apps_json(std::string&& json, const std::string& framework_id);
	void parse_apps(std::string&& json, const std::string& framework_id);

	void add_task_labels(std::string& json);

#ifdef HAS_CAPTURE
	void on_watch_data(const std::string& framework_id, mesos_event_data&& msg);
	void get_groups(marathon_http::ptr_t http, std::string& json);

	typedef std::unordered_map<int, marathon_http::ptr_t>       marathon_http_map;
	typedef std::unordered_map<int, marathon_dispatcher::ptr_t> marathon_disp_map;

	mesos_http::ptr_t m_state_http;
	marathon_http_map m_marathon_groups_http;
	marathon_http_map m_marathon_apps_http;
	marathon_http_map m_marathon_watch_http;
	mesos_collector   m_collector;
	marathon_disp_map m_dispatch;
#endif // HAS_CAPTURE

	mesos_state_t     m_state;
	bool              m_creation_logged;

	typedef std::map<std::string, std::string> json_map_type_t;
	std::string m_mesos_state_json;
	json_map_type_t m_marathon_groups_json;
	json_map_type_t m_marathon_apps_json;

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

#endif // _WIN32
