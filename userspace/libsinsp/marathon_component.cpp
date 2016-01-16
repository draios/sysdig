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
	if(m_id.empty())
	{
		throw sinsp_exception("component name cannot be empty");
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

marathon_app::marathon_app(const std::string& id) :
	marathon_component(marathon_component::MARATHON_APP, id)
{
}

marathon_app::~marathon_app()
{
}

void marathon_app::add_task(const std::string& ptask)
{
	for(auto& task : m_tasks)
	{
		if(task == ptask) { return; }
	}
	m_tasks.push_back(ptask);
}

void marathon_app::remove_task(const std::string& ptask)
{
	for(auto& task : m_tasks)
	{
		if(task == ptask)
		{
			return;
		}
	}
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

void marathon_group::print() const
{
	std::cout << get_id() << std::endl;
	for(auto& group : m_groups)
	{
		group.second->print();
	}
}


