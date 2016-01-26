//
// marathon_dispatcher.cpp
//

#include "marathon_dispatcher.h"
#include "mesos_event_data.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "utils.h"
#include <assert.h>
#include <stdexcept>
#include <algorithm>
#include <sstream>
#include <iostream>


marathon_dispatcher::marathon_dispatcher(mesos_state_t& state, const std::string& framework_id):
	m_state(state),
	m_framework_id(framework_id)
{
	g_logger.log("Created marathon_dispatcher for framework: " + framework_id, sinsp_logger::SEV_DEBUG);
}

void marathon_dispatcher::enqueue(mesos_event_data&& event_data)
{
	m_messages.emplace_back(event_data.get_data());
	dispatch();
}

void marathon_dispatcher::dispatch()
{
	for (list::iterator it = m_messages.begin(); it != m_messages.end();)
	{
		extract_data(*it);
		it = m_messages.erase(it);
	}
}

void marathon_dispatcher::extract_data(const std::string& json)
{
	Json::Value root;
	Json::Reader reader;
	if(reader.parse(json, root, false))
	{
		switch(mesos_event_data::get_event_type(root))
		{
			case mesos_event_data::MESOS_API_POST_EVENT:
				//handle_api_post(root);
				//break;
			case mesos_event_data::MESOS_STATUS_UPDATE_EVENT:
				//handle_status_update(root);
				//break;
			case mesos_event_data::MESOS_APP_TERMINATED_EVENT:
				//handle_app_terminate(root);
				//break;
			case mesos_event_data::MESOS_GROUP_CHANGE_SUCCESS_EVENT:
				//handle_group_change(root);
				//break;
			case mesos_event_data::MESOS_DEPLOYMENT_SUCCESS_EVENT:
				//handle_deployment_success(root);
				m_state.set_marathon_changed(true);
				break;
			case mesos_event_data::MESOS_IGNORED_EVENT:
				break;
			default:
			{
				std::string evt;
				Json::Value ev_type = root["eventType"];
				if(!ev_type.isNull() && ev_type.isString())
				{
					evt = ev_type.asString();
				}
				g_logger.log("marathon_dispatcher::extract_data: Unknown event " + evt, sinsp_logger::SEV_WARNING);
			}
		}
	}
}

void marathon_dispatcher::handle_status_update(const Json::Value& root)
{
	std::string slave_id = get_json_string(root, "slaveId");
	std::string app_id = get_json_string(root, "appId");
	if(!slave_id.empty() && !app_id.empty())
	{
		std::string task_status = get_json_string(root, "taskStatus");
		if(!task_status.empty())
		{
			std::string task_id = get_json_string(root, "taskId");
			if(!task_id.empty())
			{
				g_logger.log("App [" + app_id + "], task [" + task_id + "] changed status to " + task_status +
					" on slave [" + slave_id + "].\nVersion: " + get_json_string(root, "version") +
					", Timestamp: " + get_json_string(root, "version"), sinsp_logger::SEV_INFO);
				if(task_status == "TASK_RUNNING")
				{
					std::string task_name;
					std::string::size_type pos = task_id.rfind('.');
					if(pos != std::string::npos && pos > 0)
					{
						task_name = task_id.substr(0, pos);
					}
					g_logger.log("Handling running notification for task " + task_name + " [" + task_id + ']', sinsp_logger::SEV_INFO);

					std::string group_id = marathon_app::get_group_id(app_id);
					if(!group_id.empty() && m_state.get_group(group_id))
					{
						mesos_task::ptr_t t = mesos_task::make_task(root);
						if(t)
						{
							if(m_state.add_or_replace_app(app_id, group_id, task_id))
							{
								g_logger.log("Added or replaced app: " + app_id + ", group: " + group_id + ", task ID:" + task_id + ']', sinsp_logger::SEV_DEBUG);
								t->set_marathon_app_id(app_id);
								m_state.add_or_replace_task(m_state.get_framework(m_framework_id), t);
							}
							else
							{
								g_logger.log("Error adding or updating task [" + task_id + ']', sinsp_logger::SEV_ERROR);
								return;
							}
						}
						else
						{
							g_logger.log("Error creating task " + task_name + " [" + task_id + ']', sinsp_logger::SEV_ERROR);
						}
					}
					else
					{
						g_logger.log("Non-existent group ID (" + group_id + "] for task [" + task_id + ']', sinsp_logger::SEV_ERROR);
						return;
					}
				}
				else if(task_status == "TASK_FINISHED" || // TERMINAL. The task finished successfully.
					task_status == "TASK_FAILED"       || // TERMINAL. The task failed to finish successfully.
					task_status == "TASK_KILLED"       || // TERMINAL. The task was killed by the executor.
					task_status == "TASK_LOST"         || // TERMINAL. The task failed but can be rescheduled.
					task_status == "TASK_ERROR")          // TERMINAL. The task description contains an error.
				{
					std::string msg = get_json_string(root, "message");
					std::ostringstream os;
					os << "Handling removal notification for task [" << task_id << ']';
					if(!msg.empty())
					{
						os << ", termination message: " << msg;
					}
					g_logger.log(os.str(), sinsp_logger::SEV_INFO);
					try
					{
						m_state.remove_task(m_state.get_framework(m_framework_id), task_id);
					}
					catch(std::exception& ex)
					{
						g_logger.log(ex.what(), sinsp_logger::SEV_ERROR);
						return;
					}
					g_logger.log("Succesfully removed task [" + task_id + ']', sinsp_logger::SEV_INFO);
				}
				else
				{
					// Ignored:
					// TASK_STAGING; // Initial state. Framework status updates should not use.
					// TASK_STARTING;
					g_logger.log("Slave [" + slave_id + "], task " + get_json_string(root, "appId") + " (" + 
						task_id + ") ignored changed status to " + task_status, sinsp_logger::SEV_DEBUG);
				}
			}
		}
	}
}

void marathon_dispatcher::handle_api_post(const Json::Value& root)
{
	g_logger.log("MESOS_API_POST_EVENT", sinsp_logger::SEV_DEBUG);
	std::string uri = get_json_string(root, "uri");
	if(uri == "/v2/apps")
	{
		Json::Value app_obj = root["appDefinition"];
		if(!app_obj.empty())
		{
			std::string app_id = get_json_string(app_obj, "id");
			g_logger.log("Adding app [" + app_id + ']', sinsp_logger::SEV_INFO);
			std::string group_id = marathon_app::get_group_id(app_id);
			if(!group_id.empty())
			{
				m_state.add_or_replace_app(app_id, group_id);
			}
			else
			{
				g_logger.log("error adding app [" + app_id + ']', sinsp_logger::SEV_ERROR);
			}
		}
	}
}

void marathon_dispatcher::handle_app_terminate(const Json::Value& root)
{
	g_logger.log("MESOS_APP_TERMINATED_EVENT", sinsp_logger::SEV_DEBUG);
	std::string id = get_json_string(root, "appId");
	g_logger.log("Removing app [" + id + ']', sinsp_logger::SEV_INFO);
	if(!m_state.remove_app(id))
	{
		g_logger.log("App [" + id + "] not found.", sinsp_logger::SEV_ERROR);
		return;
	}
	g_logger.log("Succesfully removed app [" + id + ']', sinsp_logger::SEV_INFO);
}

void marathon_dispatcher::handle_group_change(const Json::Value& root)
{
	g_logger.log("MESOS_GROUP_CHANGE_SUCCESS_EVENT", sinsp_logger::SEV_DEBUG);
	//g_logger.log(root.toStyledString(), sinsp_logger::SEV_DEBUG);

	Json::Value group_id = root["id"];
	if(!group_id.isNull() && group_id.isString())
	{
		std::string id = group_id.asString();
		g_logger.log("Handling group [" + id + ']', sinsp_logger::SEV_INFO);
		std::string::size_type pos = id.rfind('/');
		if(pos != std::string::npos)
		{
			std::string parent_id;
			marathon_group::ptr_t parent = 0;
			if(pos == 0 && id.size() > 1)
			{
				parent = m_state.get_group("/");
			}
			else if(pos != 0)
			{
				parent_id = id.substr(0, pos);
				parent = m_state.get_group(parent_id);
			}
			if(m_state.handle_groups(root, m_state.add_group(root, parent, m_framework_id), m_framework_id))
			{
				g_logger.log("Sucesfully handled notification for group [" + id + ']', sinsp_logger::SEV_INFO);
				return;
			}
		}
		g_logger.log("An error occurred while handling group [" + id + ']', sinsp_logger::SEV_ERROR);
	}

	g_logger.log("An error occurred while handling group (no ID found)", sinsp_logger::SEV_ERROR);
}

void marathon_dispatcher::handle_deployment_success(const Json::Value& /*root*/)
{
	g_logger.log("MESOS_DEPLOYMENT_SUCCESS_EVENT", sinsp_logger::SEV_DEBUG);
}

