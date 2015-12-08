//
// mesos_component.cpp
//

#include "mesos_component.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include <sstream>
#include <iostream>

//
// component
//

const mesos_component::component_map mesos_component::list =
{
	{ mesos_component::MESOS_FRAMEWORK, "framework" },
	{ mesos_component::MESOS_TASK,      "task"      },
	{ mesos_component::MESOS_SLAVE,     "slave"     }
};

mesos_component::mesos_component(type t, const std::string& name, const std::string& uid) : 
	m_type(t),
	m_name(name), m_uid(uid)
{
	if(m_name.empty())
	{
		throw sinsp_exception("component name cannot be empty");
	}

	if(m_uid.empty())
	{
		throw sinsp_exception("component uid cannot be empty");
	}
}

mesos_component::mesos_component(const mesos_component& other): m_type(other.m_type),
	m_name(other.m_name),
	m_uid(other.m_uid),
	m_labels(other.m_labels)
{
}

mesos_component::mesos_component(mesos_component&& other):  m_type(other.m_type),
	m_name(std::move(other.m_name)),
	m_uid(std::move(other.m_uid)),
	m_labels(std::move(other.m_labels))
{
}

mesos_component& mesos_component::operator=(const mesos_component& other)
{
	m_type = other.m_type;
	m_name = other.m_name;
	m_uid = other.m_uid;
	m_labels = other.m_labels;
	return *this;
}

mesos_component& mesos_component::operator=(const mesos_component&& other)
{
	m_type = other.m_type;
	m_name = std::move(other.m_name);
	m_uid = std::move(other.m_uid);
	m_labels = other.m_labels;
	return *this;
}

std::string mesos_component::get_name(type t)
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

mesos_component::type mesos_component::get_type(const std::string& name)
{
	if(name == "framework")
	{
		return MESOS_FRAMEWORK;
	}
	else if(name == "task")
	{
		return MESOS_TASK;
	}
	else if(name == "slave")
	{
		return MESOS_SLAVE;
	}

	std::ostringstream os;
	os << "Unknown component name " << name;
	throw sinsp_exception(os.str().c_str());
}

mesos_pair_t* mesos_component::get_label(const mesos_pair_t& label)
{
	for (auto& lbl : m_labels)
	{
		if((lbl.first == label.first) && (lbl.second == label.second))
		{
			return &lbl;
		}
	}
	return 0;
}

void mesos_component::add_labels(mesos_pair_list&& labels)
{
	for (auto& label : labels)
	{
		if(!get_label(label))
		{
			emplace_label(std::move(label));
		}
	}
}


//
// framework
//

mesos_framework::mesos_framework(const std::string& name, const std::string& uid) :
	mesos_component(mesos_component::MESOS_FRAMEWORK, name, uid)
{
}

mesos_framework::~mesos_framework()
{
}

void mesos_framework::add_or_replace_task(std::shared_ptr<mesos_task> task)
{
	m_tasks.insert({task->get_uid(), task});
}

void mesos_framework::remove_task(const std::string& uid)
{
	task_map::iterator it = m_tasks.find(uid);
	if(it != m_tasks.end())
	{
		m_tasks.erase(it);
		return;
	}
	throw sinsp_exception("Removal of non-existing task attempted: " + uid);
}

const mesos_framework::task_map& mesos_framework::get_tasks() const
{
	return m_tasks;
}

mesos_framework::task_map& mesos_framework::get_tasks()
{
	return m_tasks;
}

//
// task
//

mesos_task::mesos_task(const std::string& name, const std::string& uid) :
	mesos_component(mesos_component::MESOS_TASK, name, uid)
{
}

mesos_task::mesos_task(const mesos_task& other): mesos_component(other)
{
}

mesos_task::mesos_task(mesos_task&& other): mesos_component(std::move(other))
{
}

mesos_task& mesos_task::operator=(const mesos_task& other)
{
	mesos_component::operator =(other);
	return *this;
}

mesos_task& mesos_task::operator=(const mesos_task&& other)
{
	mesos_component::operator =(std::move(other));
	return *this;
}

//
// slave
//

mesos_slave::mesos_slave(const std::string& name, const std::string& uid) :
	mesos_component(mesos_component::MESOS_SLAVE, name, uid)
{
}

