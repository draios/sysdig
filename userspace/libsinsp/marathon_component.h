//
// marathon_component.h
//
// marathon components (groups, apps, tasks)
// abstraction
//

#pragma once

#include "json/json.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "mesos_component.h"
#include <vector>
#include <map>
#include <unordered_map>
#include <memory>

typedef std::pair<std::string, std::string> marathon_pair_t;
typedef std::vector<marathon_pair_t>        marathon_pair_list;

// 
// component
//

class marathon_component
{
public:
	enum type
	{
		MARATHON_GROUP,
		MARATHON_APP
	};

	typedef std::pair<type, std::string> component_pair;
	typedef std::map<type, std::string> component_map;
	static const component_map list;

	marathon_component() = delete;

	marathon_component(type t, const std::string& id);

	marathon_component(const marathon_component& other);

	marathon_component(marathon_component&& other);

	marathon_component& operator=(const marathon_component& other);

	marathon_component& operator=(const marathon_component&& other);

	const std::string& get_id() const;

	void set_id(const std::string& name);

	static std::string get_name(type t);

	static type get_type(const std::string& name);

private:
	type        m_type;
	std::string m_id;
};

class marathon_app;

//
// group
//

class marathon_group : public marathon_component, public std::enable_shared_from_this<marathon_group>
{
public:
	typedef std::shared_ptr<marathon_group> ptr_t;
	typedef std::shared_ptr<marathon_app> app_ptr_t;

	typedef std::unordered_map<std::string, std::shared_ptr<marathon_app>> app_map_t;
	typedef std::map<std::string, std::shared_ptr<marathon_group>> group_map_t;

	marathon_group(const std::string& id);

	marathon_group(const marathon_group& other);

	marathon_group(marathon_group&& other);

	marathon_group& operator=(const marathon_group& other);

	marathon_group& operator=(const marathon_group&& other);

	void add_or_replace_app(std::shared_ptr<marathon_app>);
	void remove_app(const std::string& id);

	void add_or_replace_group(std::shared_ptr<marathon_group>);

	const app_map_t& get_apps() const;
	const group_map_t& get_groups() const;
	ptr_t get_group(const std::string& group_id);

	bool remove(const std::string& id);

	void print() const;

private:

	template <typename M, typename P>
	static void add_or_replace_component(M& component_map, P comp)
	{
		typename M::value_type val = {comp->get_id(), comp};
		std::pair<typename M::iterator, bool> ret = component_map.insert(val);
		if (!ret.second) ret.first->second = comp;
	}

	bool remove_group(const std::string& id);

	ptr_t get_parent(const std::string& id);

	app_map_t   m_apps;
	group_map_t m_groups;
};

//
// app
//

class marathon_app : public marathon_component
{
public:
	typedef std::shared_ptr<marathon_app> ptr_t;
	typedef std::vector<std::string>      task_list_t;

	marathon_app(const std::string& uid);
	~marathon_app();

	void add_task(const std::string& ptask);
	void remove_task(const std::string& ptask);
	const task_list_t& get_tasks() const;

private:
	task_list_t m_tasks;
};

typedef marathon_group::app_map_t marathon_apps;
typedef marathon_group::group_map_t marathon_groups;

//
// component
//

inline const std::string& marathon_component::get_id() const
{
	return m_id;
}

inline void marathon_component::set_id(const std::string& id)
{
	m_id = id;
}


//
// group
//

inline void marathon_group::remove_app(const std::string& id)
{
	m_apps.erase(id);
}

inline const marathon_group::app_map_t& marathon_group::get_apps() const
{
	return m_apps;
}

inline const marathon_group::group_map_t& marathon_group::get_groups() const
{
	return m_groups;
}

inline void marathon_group::add_or_replace_group(std::shared_ptr<marathon_group> group)
{
	add_or_replace_component(m_groups, group);
}

inline void marathon_group::add_or_replace_app(std::shared_ptr<marathon_app> app)
{
	add_or_replace_component(m_apps, app);
}

//
// app
//

inline const marathon_app::task_list_t& marathon_app::get_tasks() const
{
	return m_tasks;
}

