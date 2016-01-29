//
// mesos.cpp
//
#ifndef _WIN32

#include "mesos.h"
#include "mesos_component.h"
#include "sinsp.h"
#include "sinsp_int.h"

const mesos_component::component_map mesos::m_components =
{
	{ mesos_component::MESOS_FRAMEWORK, "framework" },
	{ mesos_component::MESOS_TASK,      "task"      },
	{ mesos_component::MESOS_SLAVE,     "slave"     }
};

const std::string mesos::default_state_uri    = "http://localhost:5050";
const std::string mesos::default_state_api    = "/master/state";
const std::string mesos::default_marathon_uri = "http://localhost:8080";
const std::string mesos::default_groups_api   = "/v2/groups";
const std::string mesos::default_apps_api     = "/v2/apps?embed=apps.tasks";
const std::string mesos::default_watch_api    = "/v2/events";

mesos::mesos(const std::string& state_uri,
	const std::string& state_api,
	const uri_list_t& marathon_uris,
	const std::string& groups_api,
	const std::string& apps_api,
	const std::string& /*watch_api*/): m_collector(false), m_creation_logged(false)
{
#ifdef HAS_CAPTURE
	m_state_http = std::make_shared<mesos_http>(*this, state_uri + state_api);
	rebuild_mesos_state(true);

	for(const auto& muri : marathon_uris)
	{
		int port = (muri.substr(0, 5) == "https") ? 443 : 80;
		std::string::size_type pos = muri.rfind(':');
		if(pos != std::string::npos)
		{
			std::string::size_type ppos = muri.find('/', pos);
			if(ppos == std::string::npos)
			{
				ppos = pos + (muri.length() - pos);
			}
			ASSERT(ppos - (pos + 1) > 0);
			port = std::stoi(muri.substr(pos + 1, ppos - (pos + 1)));
		}
		m_marathon_groups_http[port] = std::make_shared<marathon_http>(*this, muri + groups_api);
		m_marathon_apps_http[port]   = std::make_shared<marathon_http>(*this, muri + apps_api);
/*
		TODO: enable marathon state rebuild based on marathon change events; currently, the problem is
		the design of http_mesos/http_marathon class hierarchy - there is a virtual on_data() member,
		which can be used by either events or non-blocking full state polling, but not for both

		uri url(muri + watch_api);
		host_and_port = url.get_host();
		port = url.get_port();
		if(port)
		{
			host_and_port.append(1, ':').append(std::to_string(port));
		}
		request.str("");
		request << "GET " << url.get_path() << " HTTP/1.1\r\nHost: " << host_and_port << "\r\nAccept: text/event-stream\r\n";
		std::string creds = url.get_credentials();
		if(!creds.empty())
		{
			std::istringstream is(creds);
			std::ostringstream os;
			base64::encoder().encode(is, os);
			request << "Authorization: Basic " << os.str() << "\r\n";
		}
		request << "\r\n";
		m_marathon_watch_http[port]  = std::make_shared<marathon_http>(*this, muri + watch_api, request.str(), true);
		m_collector.add(m_marathon_watch_http[port]);
		m_dispatch[port] = std::make_shared<marathon_dispatcher>(m_state, m_marathon_watch_http[port]->get_id());
*/
	}

	if(has_marathon())
	{
		rebuild_marathon_state(true);
	}
#endif // HAS_CAPTURE
}

mesos::~mesos()
{
}

void mesos::refresh()
{
	rebuild_mesos_state();
	if(has_marathon())
	{
		//TODO: optimize - rebuild only if there was marathon change
		//watch_marathon();
		//if(m_state.get_marathon_changed())
		{
			rebuild_marathon_state();
		}
	}
}

void mesos::rebuild_mesos_state(bool full)
{
	if(full)
	{
		clear_mesos();
		m_state_http->get_all_data(&mesos::parse_state);
	}
	else
	{
		connect_mesos();
		send_mesos_data_request();
		collect_data();
	}
}

void mesos::rebuild_marathon_state(bool full)
{
	if(has_marathon())
	{
		if(full)
		{
			clear_marathon();

			for(auto& group_http : m_marathon_groups_http)
			{
				group_http.second->get_all_data(&mesos::parse_groups);
			}

			for(auto& app_http : m_marathon_apps_http)
			{
				app_http.second->get_all_data(&mesos::parse_apps);
			}
		}
		else
		{
			connect_marathon();
			send_marathon_data_request();
			collect_data();
		}

		m_state.set_marathon_changed(false);
	}
}

void mesos::send_marathon_data_request()
{
	if(has_marathon())
	{
		for(auto& group_http : m_marathon_groups_http)
		{
			group_http.second->send_request();
		}
		for(auto& app_http : m_marathon_apps_http)
		{
			app_http.second->send_request();
		}
	}
}

void mesos::connect_marathon()
{
	if(has_marathon())
	{
		for(auto& group_http : m_marathon_groups_http)
		{
			connect(group_http.second, &mesos::set_marathon_groups_json);
		}
		for(auto& app_http : m_marathon_apps_http)
		{
			connect(app_http.second, &mesos::set_marathon_apps_json);
		}
	}
}

void mesos::send_mesos_data_request()
{
	m_state_http->send_request();
}

void mesos::connect_mesos()
{
	connect(m_state_http, &mesos::set_state_json);
}

bool mesos::is_alive() const
{
#ifdef HAS_CAPTURE
	if(!m_state_http->is_connected())
	{
		g_logger.log("Mesos state connection loss.", sinsp_logger::SEV_WARNING);
		return false;
	}

	for(const auto& group : m_marathon_groups_http)
	{
		if(!group.second->is_connected())
		{
			g_logger.log("Marathon groups connection loss.", sinsp_logger::SEV_WARNING);
			return false;
		}
	}

	for(const auto& app : m_marathon_apps_http)
	{
		if(!app.second->is_connected())
		{
			g_logger.log("Marathon apps connection loss.", sinsp_logger::SEV_WARNING);
			return false;
		}
	}
#endif // HAS_CAPTURE
	return true;
}

void mesos::watch_marathon()
{
#ifdef HAS_CAPTURE
	if(has_marathon())
	{
		if(m_marathon_watch_http.size())
		{
			if(!m_collector.subscription_count())
			{
				for(auto watch_http : m_marathon_watch_http)
				{
					m_collector.add(watch_http.second);
				}
			}
			m_collector.get_data();
		}
	}
	else
	{
		throw sinsp_exception("Attempt to watch non-existing Marathon framework.");
	}
#endif // HAS_CAPTURE
}

void mesos::add_task_labels(std::string& json)
{
#ifdef HAS_CAPTURE
	Json::Value root;
	Json::Reader reader;
	try
	{
		if(reader.parse(json, root, false))
		{
			if(mesos_event_data::get_event_type(root) == mesos_event_data::MESOS_STATUS_UPDATE_EVENT)
			{
				if(!root["taskId"].isNull())
				{
					if(!root["taskStatus"].isNull() && root["taskStatus"].isString() && root["taskStatus"].asString() == "TASK_RUNNING")
					{
						Json::Value labels = m_state_http->get_task_labels(root["taskId"].asString());
						if(!labels.isNull() && labels.isArray())
						{
							root["labels"] = labels;
							json = Json::FastWriter().write(root);
						}
					}
				}
			}
		}
		else
		{
			g_logger.log("Error parsing task update message.\nJSON:\n---\n" + json + "\n---", sinsp_logger::SEV_ERROR);
		}
	}
	catch(std::exception& ex)
	{
		g_logger.log(std::string("Error while looking for taks labels:") + ex.what(), sinsp_logger::SEV_ERROR);
	}
#endif // HAS_CAPTURE
}

#ifdef HAS_CAPTURE
void mesos::get_groups(marathon_http::ptr_t http, std::string& json)
{
	std::string group_ev_type = mesos_event_data::m_events[mesos_event_data::MESOS_GROUP_CHANGE_SUCCESS_EVENT];
	Json::Value root;
	Json::Reader reader;
	try
	{
		if(reader.parse(json, root, false))
		{
			Json::Value event_type = root["eventType"];
			if(!event_type.isNull() && event_type.isString() && event_type.asString() == group_ev_type)
			{
				Json::Value group_id = root["groupId"];
				if(!group_id.isNull() && group_id.isString())
				{
					std::string gid = group_id.asString();
					if(!gid.empty())
					{
						json = http->get_groups(gid);
						if(reader.parse(json, root, false))
						{
							root["eventType"] = group_ev_type;
							json = Json::FastWriter().write(root);
						}
					}
				}
			}
		}
		else
		{
			g_logger.log("Error parsing task update message.\nJSON:\n---\n" + json + "\n---", sinsp_logger::SEV_ERROR);
		}
	}
	catch(std::exception& ex)
	{
		g_logger.log(std::string("Error while looking for taks labels:") + ex.what(), sinsp_logger::SEV_ERROR);
	}
}

void mesos::on_watch_data(const std::string& framework_id, mesos_event_data&& msg)
{
	for(auto& dispatcher : m_dispatch)
	{
		if(framework_id == dispatcher.second->get_id())
		{
			dispatcher.second->enqueue(std::move(msg));
			break;
		}
	}
}
#endif // HAS_CAPTURE

void mesos::handle_frameworks(const Json::Value& root)
{
	Json::Value frameworks = root["frameworks"];
	if(!frameworks.isNull())
	{
		for(const auto& framework : frameworks)
		{
			add_framework(framework);
		}
	}
	else
	{
		g_logger.log("No frameworks found.", sinsp_logger::SEV_WARNING);
	}
}

void mesos::handle_slaves(const Json::Value& root)
{
	Json::Value slaves = root["slaves"];
	if(!slaves.isNull())
	{
		for(const auto& slave : slaves)
		{
			add_slave(slave);
		}
	}
	else
	{
		g_logger.log("No frameworks found.", sinsp_logger::SEV_WARNING);
	}
}

void mesos::add_framework(const Json::Value& framework)
{
	std::string name, uid;
	Json::Value fname = framework["name"];
	Json::Value fid = framework["id"];
	if(!fname.isNull())
	{
		name = fname.asString();
	}
	if(!fid.isNull())
	{
		uid = fid.asString();
	}
	if(!m_creation_logged)
	{
		std::ostringstream os;
		os << "Adding Mesos framework: [" << name << ',' << uid << ']';
		g_logger.log(os.str(), sinsp_logger::SEV_DEBUG);
	}
	m_state.emplace_framework(mesos_framework(name, uid));
	add_tasks(m_state.get_frameworks().back(), framework);
}

void mesos::add_slave(const Json::Value& slave)
{
	std::string name, uid;
	Json::Value sname = slave["hostname"];
	Json::Value sid = slave["id"];
	if(!sname.isNull())
	{
		name = sname.asString();
	}
	if(!sid.isNull())
	{
		uid = sid.asString();
	}
	if(!m_creation_logged)
	{
		std::ostringstream os;
		os << "Adding Mesos slave: [" << name << ',' << uid << ']';
		g_logger.log(os.str(), sinsp_logger::SEV_DEBUG);
	}
	m_state.emplace_slave(mesos_slave(name, uid));
}

void mesos::add_tasks_impl(mesos_framework& framework, const Json::Value& tasks)
{
	if(!tasks.isNull())
	{
		for(const auto& task : tasks)
		{
			mesos_task::ptr_t t = mesos_task::make_task(task);
			std::ostringstream os;
			if(t)
			{
				os << "Adding Mesos task: [" << framework.get_name() << ':' << t->get_name() << ',' << t->get_uid() << ']';
				g_logger.log(os.str(), sinsp_logger::SEV_DEBUG);
				m_state.add_or_replace_task(framework, t);
			}
			else
			{
				std::string name, uid, sid;
				Json::Value fname = task["name"];
				if(!fname.isNull()) { name = fname.asString(); }
				Json::Value fid = task["id"];
				if(!fid.isNull()) { uid = fid.asString(); }
				Json::Value fsid = task["slave_id"];
				if(!fsid.isNull()) { sid = fsid.asString(); }
				os << "Failed to add Mesos task: [" << framework.get_name() << ':' << name << ',' << uid << "], running on slave " << sid;
				g_logger.log(os.str(), sinsp_logger::SEV_ERROR);
			}
		}
	}
	else
	{
		g_logger.log("Tasks is null", sinsp_logger::SEV_ERROR);
	}
}

void mesos::add_tasks(mesos_framework& framework, const Json::Value& f_val)
{
	Json::Value tasks = f_val["tasks"];
	add_tasks_impl(framework, tasks);
}

void mesos::set_state_json(std::string&& json, const std::string&)
{
	if(!json.empty())
	{
		//g_logger.log("Received state JSON " + std::to_string(json.size()), sinsp_logger::SEV_DEBUG);
		m_mesos_state_json = std::move(json);
	}
	else
	{
		g_logger.log("Received empty state JSON", sinsp_logger::SEV_WARNING);
	}
}

void mesos::parse_state(std::string&& json, const std::string&)
{
	Json::Value root;
	Json::Reader reader;
	if(reader.parse(json, root, false))
	{
		clear_mesos();
		handle_frameworks(root);
		handle_slaves(root);
		if(!m_creation_logged)
		{
			m_creation_logged = true;
		}
	}
	else
	{
		throw sinsp_exception("Invalid JSON (parsing Mesos state failed).");
	}
}

void mesos::set_marathon_groups_json(std::string&& json, const std::string& framework_id)
{
	if(!json.empty())
	{
		m_marathon_groups_json[framework_id] = std::move(json);
	}
	else
	{
		g_logger.log("Received empty groups JSON", sinsp_logger::SEV_WARNING);
	}
}

void mesos::parse_groups(std::string&& json, const std::string& framework_id)
{
	m_state.parse_groups(std::move(json), framework_id);
}

void mesos::set_marathon_apps_json(std::string&& json, const std::string& framework_id)
{
	if(!json.empty())
	{
		g_logger.log("Received apps JSON (" + std::to_string(json.size()) + " bytes) for framework [" + framework_id + ']', sinsp_logger::SEV_DEBUG);
		m_marathon_apps_json[framework_id] = std::move(json);
	}
	else
	{
		g_logger.log("Received empty apps JSON", sinsp_logger::SEV_WARNING);
	}
}

void mesos::parse_apps(std::string&& json, const std::string& framework_id)
{
	m_state.parse_apps(std::move(json), framework_id);
}

#endif // _WIN32
