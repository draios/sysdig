//
// mesos.h
//

#pragma once

#include "json/json.h"
#include "mesos_common.h"
#include "mesos_component.h"
#include "mesos_http.h"
#include "mesos_state.h"
#include "uri.h"
#include <sstream>
#include <utility>

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
	static const std::string default_groups_uri;
	static const std::string default_groups_api;
	static const std::string default_apps_uri;
	static const std::string default_apps_api;

	mesos(const std::string& state_uri = default_state_uri,
		const std::string& state_api = default_state_api,
		const std::string& groups_uri = "",
		const std::string& groups_api = "",
		const std::string& apps_uri = "",
		const std::string& apps_api = "");

	~mesos();

	node_t get_node_type() const;
	const mesos_state_t get_state() const;
	bool is_alive() const;

private:
	void init();

	void parse_state(const std::string& json);
	void determine_node_type(const Json::Value& root);
	bool is_master() const;
	void handle_frameworks(const Json::Value& root);
	void add_framework(const Json::Value& framework);
	void add_tasks(mesos_framework& framework, const Json::Value& f_val);
	void add_tasks_impl(mesos_framework& framework, const Json::Value& tasks);
	void add_labels(std::shared_ptr<mesos_task> task, const Json::Value& t_val);
	void handle_slaves(const Json::Value& root);
	void add_slave(const Json::Value& framework);

	void parse_groups(const std::string& json);
	void handle_groups(const Json::Value& groups, marathon_group::ptr_t p_groups);
	marathon_group::ptr_t add_group(const Json::Value& group, marathon_group::ptr_t to_group);

	void parse_apps(const std::string& json);
	void add_app(const Json::Value& app);

	std::string   m_container_id;
	node_t        m_node_type;
	mesos_http    m_state_http;
	mesos_http*   m_groups_http;
	mesos_http*   m_apps_http;
	mesos_state_t m_state;

	static const mesos_component::component_map m_components;
};

inline mesos::node_t mesos::get_node_type() const
{
	return m_node_type;
}

inline const mesos_state_t mesos::get_state() const
{
	return m_state;
}

inline bool mesos::is_master() const
{
	return m_node_type == NODE_MASTER;
}

inline bool mesos::is_alive() const
{
	return m_state_http.is_connected() &&
		(!m_groups_http || m_groups_http->is_connected()) &&
		(!m_apps_http || m_apps_http->is_connected());
}
