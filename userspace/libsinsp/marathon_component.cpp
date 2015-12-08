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

void marathon_app::add_or_replace_task(mesos_task::ptr_t ptask)
{
	for(auto& task : m_tasks)
	{
		if(task->get_uid() == ptask->get_uid())
		{
			task = ptask;
			return;
		}
	}
	m_tasks.push_back(ptask);
}

//
// group
//

marathon_group::marathon_group(const std::string& id) :
	marathon_component(marathon_component::MARATHON_GROUP, id)
{
}

marathon_group::marathon_group(const marathon_group& other): marathon_component(other)
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
