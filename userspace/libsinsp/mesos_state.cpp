//
// k8s_state.cpp
//

#include "mesos_state.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include <sstream>
#include <iostream>
#include <memory>

//
// state
//

mesos_state_t::mesos_state_t(bool is_captured) : m_is_captured(is_captured)
{
}

mesos_framework::task_ptr_t mesos_state_t::get_task(const std::string& uid)
{
	for(auto& framework : get_frameworks())
	{
		for(auto& task : framework.get_tasks())
		{
			if(task.first == uid)
			{
				return task.second;
			}
		}
	}
	throw sinsp_exception("Task not found: " + uid);
}

const mesos_framework::task_map& mesos_state_t::get_tasks(const std::string& framework_uid) const
{
	for(const auto& framework : m_frameworks)
	{
		if(framework.get_uid() == framework_uid)
		{
			return framework.get_tasks();
		}
	}
	throw sinsp_exception("Framework not found: " + framework_uid);
}

mesos_framework::task_map& mesos_state_t::get_tasks(const std::string& framework_uid)
{
	for(auto& framework : m_frameworks)
	{
		if(framework.get_uid() == framework_uid)
		{
			return framework.get_tasks();
		}
	}
	throw sinsp_exception("Framework not found: " + framework_uid);
}

marathon_app::ptr_t mesos_state_t::get_app(const std::string& app_id)
{
	marathon_apps::iterator it = m_apps.find(app_id);
	if(it != m_apps.end())
	{
		return it->second;
	}
	return 0;
}

void mesos_state_t::add_or_replace_app(marathon_group::app_ptr_t app)
{
	std::string id = app->get_id();
	marathon_apps::iterator it = m_apps.find(id);
	if(it != m_apps.end())
	{
		m_apps.erase(it);
	}
	m_apps.insert({id, app});
}

marathon_group::ptr_t mesos_state_t::get_group(const std::string& group_id)
{
	marathon_groups::iterator it = m_groups.find(group_id);
	if(it != m_groups.end())
	{
		return it->second;
	}
	return 0;
}

marathon_group::ptr_t mesos_state_t::add_or_replace_group(marathon_group::ptr_t group, marathon_group::ptr_t to_group)
{
	std::string id = group->get_id();
	if(!to_group) // top level
	{
		marathon_groups::iterator it = m_groups.find(id);
		if(it != m_groups.end())
		{
			m_groups.erase(it);
		}
		m_groups.insert({id, group});
	}
	else
	{
		to_group->add_or_replace_group(group);
	}
	return group;
}
