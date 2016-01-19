//
// mesos_state_t.h
//
// mesos state abstraction
//

#pragma once

#include "mesos_component.h"
#include "marathon_component.h"
#include "json/json.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include <vector>
#include <map>
#include <unordered_map>

//
// state
//

class mesos_state_t
{
public:
	mesos_state_t(bool is_captured = false);

	//
	// frameworks
	//

	const mesos_frameworks& get_frameworks() const;

	mesos_frameworks& get_frameworks();

	const mesos_framework& get_framework(const std::string& framework_uid) const;

	mesos_framework& get_framework(const std::string& framework_uid);

	void push_framework(const mesos_framework& framework);

	void emplace_framework(mesos_framework&& framework);

	//
	// tasks
	//

	const mesos_framework::task_map& get_tasks(const std::string& framework_uid) const;

	mesos_framework::task_map& get_tasks(const std::string& framework_uid);

	mesos_framework::task_ptr_t get_task(const std::string& uid);

	void add_or_replace_task(mesos_framework& framework, std::shared_ptr<mesos_task> task);

	void remove_task(mesos_framework& framework, const std::string& uid);

	//
	// slaves
	//

	const mesos_slaves& get_slaves() const;

	mesos_slaves& get_slaves();

	const mesos_slave& get_slave(const std::string& slave_uid) const;

	mesos_slave& get_slave(const std::string& slave_uid);

	void push_slave(const mesos_slave& slave);

	void emplace_slave(mesos_slave&& slave);

	//
	// apps
	//

	void parse_apps(const std::string& json);

	const marathon_apps& get_apps() const;

	marathon_apps& get_apps();

	marathon_app::ptr_t get_app(const std::string& app_id);

	void add_or_replace_app(marathon_group::app_ptr_t app);

	bool remove_app(const std::string& id);

	//
	// groups
	//

	bool parse_groups(const std::string& json);

	const marathon_groups& get_groups() const;

	marathon_groups& get_groups();

	marathon_group::ptr_t get_group(const std::string& group_id);

	marathon_group::ptr_t add_or_replace_group(marathon_group::ptr_t group, marathon_group::ptr_t to_group = 0);

	//
	// state
	//

	void clear(bool marathon = false);

	void print_groups() const;

private:
	marathon_group::ptr_t add_group(const Json::Value& group, marathon_group::ptr_t to_group);
	bool handle_groups(const Json::Value& groups, marathon_group::ptr_t p_groups);
	marathon_app::ptr_t add_app(const Json::Value& app);

	mesos_frameworks m_frameworks;
	mesos_slaves     m_slaves;
	marathon_apps    m_apps;
	marathon_groups  m_groups;
	bool             m_is_captured;

	friend class marathon_dispatcher;
};

//
// frameworks
//

inline const mesos_frameworks& mesos_state_t::get_frameworks() const
{
	return m_frameworks;
}

inline mesos_frameworks& mesos_state_t::get_frameworks()
{
	return m_frameworks;
}

inline const mesos_framework& mesos_state_t::get_framework(const std::string& framework_uid) const
{
	for(const auto& framework : m_frameworks)
	{
		if(framework.get_uid() == framework_uid)
		{
			return framework;
		}
	}
	throw sinsp_exception("Framework not found: " + framework_uid);
}

inline mesos_framework& mesos_state_t::get_framework(const std::string& framework_uid)
{
	for(auto& framework : m_frameworks)
	{
		if(framework.get_uid() == framework_uid)
		{
			return framework;
		}
	}
	throw sinsp_exception("Framework not found: " + framework_uid);
}

inline void mesos_state_t::push_framework(const mesos_framework& framework)
{
	m_frameworks.push_back(framework);
}

inline void mesos_state_t::emplace_framework(mesos_framework&& framework)
{
	m_frameworks.emplace_back(std::move(framework));
}

inline void mesos_state_t::add_or_replace_task(mesos_framework& framework, std::shared_ptr<mesos_task> task)
{
	framework.add_or_replace_task(task);
}

inline void mesos_state_t::remove_task(mesos_framework& framework, const std::string& uid)
{
	framework.remove_task(uid);
}

//
// slaves
//

inline const mesos_slaves& mesos_state_t::get_slaves() const
{
	return m_slaves;
}

inline mesos_slaves& mesos_state_t::get_slaves()
{
	return m_slaves;
}

inline const mesos_slave& mesos_state_t::get_slave(const std::string& slave_uid) const
{
	for(const auto& slave : m_slaves)
	{
		if(slave.get_uid() == slave_uid)
		{
			return slave;
		}
	}
	throw sinsp_exception("Slave not found: " + slave_uid);
}

inline mesos_slave& mesos_state_t::get_slave(const std::string& slave_uid)
{
	for(auto& slave : m_slaves)
	{
		if(slave.get_uid() == slave_uid)
		{
			return slave;
		}
	}
	throw sinsp_exception("Slave not found: " + slave_uid);
}

inline void mesos_state_t::push_slave(const mesos_slave& slave)
{
	m_slaves.push_back(slave);
}

inline void mesos_state_t::emplace_slave(mesos_slave&& slave)
{
	m_slaves.emplace_back(std::move(slave));
}

//
// apps
//

inline const marathon_apps& mesos_state_t::get_apps() const
{
	return m_apps;
}

inline marathon_apps& mesos_state_t::get_apps()
{
	return m_apps;
}

//
// groups
//

inline const marathon_groups& mesos_state_t::get_groups() const
{
	return m_groups;
}

inline marathon_groups& mesos_state_t::get_groups()
{
	return m_groups;
}

//
// state
//

inline void mesos_state_t::clear(bool marathon)
{
	m_frameworks.clear();
	m_slaves.clear();
	if(marathon)
	{
		m_apps.clear();
		m_groups.clear();
	}
}
