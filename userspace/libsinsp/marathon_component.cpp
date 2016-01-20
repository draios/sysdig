//
// marathon_component.cpp
//

#include "marathon_component.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include <sstream>
#include <iostream>

//
// component
//

const marathon_component::component_map marathon_component::list =
{
	{ marathon_component::MARATHON_GROUP, "group" },
	{ marathon_component::MARATHON_APP,   "app"   }
};

marathon_component::marathon_component(type t, const std::string& id) : 
	m_type(t),
	m_id(id)
{
	component_map::const_iterator it = list.find(t);
	if(it == list.end())
	{
		throw sinsp_exception("Invalid Marathon component type: " + std::to_string(t));
	}

	if(m_id.empty())
	{
		throw sinsp_exception("Marathon " + it->second + " ID cannot be empty");
	}
}

marathon_component::marathon_component(const marathon_component& other): m_type(other.m_type),
	m_id(other.m_id)
{
}

marathon_component::marathon_component(marathon_component&& other):  m_type(other.m_type),
	m_id(std::move(other.m_id))
{
}

marathon_component& marathon_component::operator=(const marathon_component& other)
{
	m_type = other.m_type;
	m_id = other.m_id;
	return *this;
}

marathon_component& marathon_component::operator=(const marathon_component&& other)
{
	m_type = other.m_type;
	m_id = std::move(other.m_id);
	return *this;
}

std::string marathon_component::get_name(type t)
{
	component_map::const_iterator it = list.find(t);
	if(it != list.end())
	{
		return it->second;
	}

	std::ostringstream os;
	os << "Unknown component type " << static_cast<int>(t);
	throw sinsp_exception(os.str().c_str());
}

marathon_component::type marathon_component::get_type(const std::string& name)
{
	if(name == "group")
	{
		return MARATHON_GROUP;
	}
	else if(name == "app")
	{
		return MARATHON_APP;
	}

	std::ostringstream os;
	os << "Unknown component name " << name;
	throw sinsp_exception(os.str().c_str());
}

//
// app
//

void marathon_app_cache::add(const std::string& app, const std::string& task)
{
	map_t::iterator it = m_app_map.find(app);
	if(it == m_app_map.end())
	{
		 it = insert({app, {task}});
		 return;
	}
	it->second.insert(task);
}

bool marathon_app_cache::remove(const std::string& app, const std::string& task)
{
	map_t::iterator it = m_app_map.find(app);
	if(it == m_app_map.end())
	{
		 return false;
	}
	it->second.erase(task);
	if(!it->second.size())
	{
		m_app_map.erase(it);
	}
	return true;
}

bool marathon_app_cache::remove(const std::string& app)
{
	map_t::iterator it = m_app_map.find(app);
	if(it == m_app_map.end()) { return false; }
	m_app_map.erase(it);
	return true;
}

const marathon_app_cache::map_t& marathon_app_cache::get() const
{
	return m_app_map;
}

void marathon_app_cache::clear()
{
	m_app_map.clear();
}

marathon_app_cache::map_t::iterator marathon_app_cache::insert(const map_t::value_type& val)
{
	std::pair<map_t::iterator, bool> ret = m_app_map.insert(val);
	if (!ret.second) ret.first->second = val.second;
	return ret.first;
}

marathon_app_cache marathon_app::m_cache;

marathon_app::marathon_app(const std::string& id) :
	marathon_component(marathon_component::MARATHON_APP, id)
{
}

marathon_app::~marathon_app()
{
}

void marathon_app::add_task(const std::string& task_id)
{
	for(auto& task : m_tasks)
	{
		if(task == task_id) { return; }
	}
	m_tasks.push_back(task_id);
	m_cache.add(get_id(), task_id);
}

bool marathon_app::remove_task(const std::string& task_id)
{
	for(auto it = m_tasks.begin(); it != m_tasks.end(); ++it)
	{
		if(task_id == *it)
		{
			m_tasks.erase(it);
			m_cache.remove(get_id(), task_id);
			return true;
		}
	}
	return false;
}

std::string marathon_app::get_group_id() const
{
	return get_group_id(get_id());
}

std::string marathon_app::get_group_id(const std::string& app_id)
{
	std::string group_id;
	std::string::size_type pos = app_id.rfind('/');
	if(pos != std::string::npos && app_id.length() > pos)
	{
		group_id = app_id.substr(0, pos + 1);
	}
	return group_id;
}

//
// group
//

marathon_group::marathon_group(const std::string& id) :
	marathon_component(marathon_component::MARATHON_GROUP, id)
{
}

marathon_group::marathon_group(const marathon_group& other): marathon_component(other),
	std::enable_shared_from_this<marathon_group>()
{
}

marathon_group::marathon_group(marathon_group&& other): marathon_component(std::move(other))
{
}

marathon_group& marathon_group::operator=(const marathon_group& other)
{
	marathon_component::operator =(other);
	return *this;
}

marathon_group& marathon_group::operator=(const marathon_group&& other)
{
	marathon_component::operator =(std::move(other));
	return *this;
}

marathon_group::app_ptr_t marathon_group::get_app(const std::string& id)
{
	for(const auto& app : m_apps)
	{
		if(app.second && app.second->get_id() == id)
		{
			return app.second;
		}
	}
	return 0;
}

marathon_group::ptr_t marathon_group::get_group(const std::string& group_id)
{
	if(group_id == get_id())
	{
		return shared_from_this();
	}

	marathon_groups::iterator it = m_groups.find(group_id);
	if(it != m_groups.end())
	{
		return it->second;
	}
	else
	{
		for(auto group : m_groups)
		{
			if(ptr_t p_group = group.second->get_group(group_id))
			{
				return p_group;
			}
		}
	}
	return 0;
}

bool marathon_group::remove(const std::string& id)
{
	if(id == get_id())
	{
		throw sinsp_exception("Invalid access - group can not remove itself.");
	}

	if(ptr_t group = get_parent(id))
	{
		return group->remove_group(id);
	}

	return false;
}

marathon_group::ptr_t marathon_group::get_parent(const std::string& id)
{
	marathon_groups::iterator it = m_groups.find(id);
	if(it != m_groups.end())
	{
		return shared_from_this();
	}
	else
	{
		for(auto group : m_groups)
		{
			if(group.second->get_group(id))
			{
				return group.second;
			}
		}
	}
	return 0;
}

bool marathon_group::remove_group(const std::string& id)
{
	marathon_groups::iterator it = m_groups.find(id);
	if(it != m_groups.end())
	{
		m_groups.erase(it);
		return true;
	}
	return false;
}

bool marathon_group::remove_app(const std::string& id)
{
	auto it = m_apps.find(id);
	if(it != m_apps.end())
	{
		m_apps.erase(id);
		return true;
	}
	return false;
}

bool marathon_group::remove_task(const std::string& id)
{
	for(auto& app : m_apps)
	{
		if(app.second && app.second->remove_task(id))
		{
			return true;
		}
	}
	return false;
}

void marathon_group::print() const
{
	std::cout << get_id() << std::endl;
	for(auto& group : m_groups)
	{
		group.second->print();
	}
}


