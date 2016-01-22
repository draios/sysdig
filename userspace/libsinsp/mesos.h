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
	enum node_t
	{
		NODE_MASTER,
		NODE_SLAVE
	};

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

	node_t get_node_type() const;
	const mesos_state_t& get_state() const;
	bool is_alive() const;
	void refresh(bool marathon = false);
	void clear(bool marathon = false);

	bool has_marathon() const;
	void watch();
private:

	void on_watch_data(const std::string& framework_id, mesos_event_data&& msg);
	void parse_state(const std::string& json);
	void determine_node_type(const Json::Value& root);
	bool is_master() const;
	void handle_frameworks(const Json::Value& root);
	void add_framework(const Json::Value& framework);
	void add_tasks(mesos_framework& framework, const Json::Value& f_val);
	void add_tasks_impl(mesos_framework& framework, const Json::Value& tasks);
	void handle_slaves(const Json::Value& root);
	void add_slave(const Json::Value& framework);

	void parse_groups(const std::string& json);
	void parse_apps(const std::string& json);

	void add_task_labels(std::string& json);
	void get_groups(marathon_http::ptr_t http, std::string& json);

	typedef std::unordered_map<int, marathon_http::ptr_t>       marathon_http_map;
	typedef std::unordered_map<int, marathon_dispatcher::ptr_t> marathon_disp_map;

	node_t            m_node_type;
	mesos_http        m_state_http;
	marathon_http_map m_marathon_groups_http;
	marathon_http_map m_marathon_apps_http;
	marathon_http_map m_marathon_watch_http;
	mesos_state_t     m_state;
	marathon_disp_map m_dispatch;
	mesos_collector   m_collector;
	bool              m_creation_logged;

	static const mesos_component::component_map m_components;

	friend class mesos_http;
	friend class marathon_http;
};

inline mesos::node_t mesos::get_node_type() const
{
	return m_node_type;
}

inline const mesos_state_t& mesos::get_state() const
{
	return m_state;
}

inline bool mesos::is_master() const
{
	return m_node_type == NODE_MASTER;
}

inline bool mesos::has_marathon() const
{
	return m_marathon_watch_http.size() > 0;
}

inline void mesos::clear(bool marathon)
{
	m_state.clear(marathon);
}

#endif // _WIN32
