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

bool mesos_state_t::remove_app(const std::string& id)
{
	marathon_apps::iterator it = m_apps.find(id);
	if(it != m_apps.end())
	{
		m_apps.erase(it);
		return true;
	}
	return false;
}

marathon_group::ptr_t mesos_state_t::get_group(const std::string& group_id)
{
	marathon_groups::iterator it = m_groups.find(group_id);
	if(it != m_groups.end())
	{
		return it->second;
	}
	else
	{
		for(auto group : m_groups)
		{
			if(marathon_group::ptr_t p_group = group.second->get_group(group_id))
			{
				return p_group;
			}
		}
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

bool mesos_state_t::handle_groups(const Json::Value& root, marathon_group::ptr_t to_group)
{
	Json::Value groups = root["groups"];
	if(!groups.isNull() && groups.isArray())
	{
		for(const auto& group : groups)
		{
			to_group = add_group(group, to_group);
			ASSERT(to_group);
			handle_groups(group, to_group);
		}
	}
	else
	{
		g_logger.log("No groups found.", sinsp_logger::SEV_WARNING);
		return false;
	}
	return true;
}

bool mesos_state_t::parse_groups(const std::string& json)
{
	Json::Value root;
	Json::Reader reader;
	if(reader.parse(json, root, false))
	{
		return handle_groups(root, add_group(root, 0));
	}
	else
	{
		throw sinsp_exception("Invalid JSON (Marathon groups parsing failed).");
	}
}

void mesos_state_t::print_groups() const
{
	for(auto& group : m_groups)
	{
		group.second->print();
	}
}

marathon_group::ptr_t mesos_state_t::add_group(const Json::Value& group, marathon_group::ptr_t to_group)
{
	Json::Value group_id = group["id"];
	if(!group_id.isNull())
	{
		std::string id = group_id.asString();
		std::ostringstream os;
		os << "Adding Marathon group [" + id + ']';
		if(to_group)
		{
			os << " to group [" + to_group->get_id() << ']';
		}
		g_logger.log(os.str(), sinsp_logger::SEV_INFO);
		marathon_group::ptr_t pg(new marathon_group(id));
		marathon_group::ptr_t p_group = add_or_replace_group(pg, to_group);
		Json::Value apps = group["apps"];
		if(!apps.isNull())
		{
			for(const auto& app : apps)
			{
				Json::Value app_id = app["id"];
				if(!app_id.isNull())
				{
					marathon_app::ptr_t p_app = get_app(app_id.asString());
					if(!p_app)
					{
						p_app = add_app(app);
					}
					if(p_app)
					{
						p_group->add_or_replace_app(p_app);
					}
					else
					{
						g_logger.log("An error occured adding app [" + app_id.asString() +
									"] to group [" + id + ']', sinsp_logger::SEV_ERROR);
					}
				}
			}
		}
		return p_group;
	}
	return 0;
}

void mesos_state_t::parse_apps(const std::string& json)
{
	Json::Value root;
	Json::Reader reader;
	if(reader.parse(json, root, false))
	{
		//g_logger.log(root.toStyledString(), sinsp_logger::SEV_DEBUG);
		Json::Value apps = root["apps"];
		if(!apps.isNull())
		{
			for(const auto& app : apps)
			{
				add_app(app);
			}
		}
		else
		{
			g_logger.log("No apps found.", sinsp_logger::SEV_WARNING);
		}
	}
	else
	{
		throw sinsp_exception("Invalid JSON (Marathon apps parsing failed).");
	}
}

marathon_app::ptr_t mesos_state_t::add_app(const Json::Value& app)
{
	Json::Value app_id = app["id"];
	if(!app_id.isNull())
	{
		std::string id = app_id.asString();
		g_logger.log("Adding Marathon app: " + id, sinsp_logger::SEV_DEBUG);
		marathon_app::ptr_t p_app(new marathon_app(id));
		add_or_replace_app(p_app);
		Json::Value tasks = app["tasks"];
		for(const auto& task : tasks)
		{
			Json::Value task_id = task["id"];
			if(!task_id.isNull())
			{
				g_logger.log("Adding Mesos task ID to app: " + task_id.asString(), sinsp_logger::SEV_DEBUG);
				mesos_framework::task_ptr_t pt = get_task(task_id.asString());
				if(pt)
				{
					pt->set_app_id(id);
					p_app->add_task(pt->get_uid());
					return p_app;
				}
				else
				{
					throw sinsp_exception("Marathon task not found in mesos state");
				}
			}
		}
	}
	return 0;
}

