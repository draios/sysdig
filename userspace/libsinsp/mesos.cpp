//
// mesos.cpp
//

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
	const std::string& /*watch_api*/):
#ifdef HAS_CAPTURE
		m_collector(false),
		m_marathon_uris(marathon_uris),
#endif // HAS_CAPTURE
		m_creation_logged(false)
{
	init(state_uri);
}

void mesos::init(const std::string& state_uri)
{
#ifdef HAS_CAPTURE
	std::string mesos_uri = state_uri;
	m_collector.remove_all();
	if(m_state_http)
	{
		if(mesos_uri.empty())
		{
			const uri& url = m_state_http->get_url();
			std::string scheme = url.get_scheme();
			std::string creds = url.get_credentials();
			if(!creds.empty()) creds.append(1, '@');
			mesos_uri = scheme + "://" + creds + url.get_host();
			int port = url.get_port();
			if(!port)
			{
				if(scheme == "http") port = 80;
				else if(scheme == "https") port = 443;
			}
			mesos_uri.append(1, ':').append(std::to_string(port));
		}
		if(!m_state_http.unique())
		{
			throw sinsp_exception("Invalid access to Mesos initializer: mesos state http client for [" +
								  mesos_uri + "] not unique.");
		}
		m_state_http.reset();
	}

	m_state_http = std::make_shared<mesos_http>(*this, mesos_uri + default_state_api);
	rebuild_mesos_state(true);

	m_marathon_groups_http.clear();
	m_marathon_apps_http.clear();

	const uri_list_t& marathons = m_marathon_uris.size() ? m_marathon_uris : m_state_http->get_marathon_uris();
	for(const auto& muri : marathons)
	{
		m_marathon_groups_http[muri] = std::make_shared<marathon_http>(*this, muri + default_groups_api);
		m_marathon_apps_http[muri]   = std::make_shared<marathon_http>(*this, muri + default_apps_api);
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
		rebuild_marathon_state();
	}
}

void mesos::rebuild_mesos_state(bool full)
{
#ifdef HAS_CAPTURE
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
#endif // HAS_CAPTURE
}

void mesos::rebuild_marathon_state(bool full)
{
#ifdef HAS_CAPTURE
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
#endif // HAS_CAPTURE
}

#ifdef HAS_CAPTURE
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
			if(!connect(group_http.second, &mesos::set_marathon_groups_json, 2))
			{
				throw sinsp_exception("Connection to Marathon group API failed.");
			}
		}
		for(auto& app_http : m_marathon_apps_http)
		{
			if(!connect(app_http.second, &mesos::set_marathon_apps_json, 3))
			{
				throw sinsp_exception("Connection to Marathon app API failed.");
			}
		}
	}
}

void mesos::send_mesos_data_request()
{
	m_state_http->send_request();
}

void mesos::connect_mesos()
{
	if(!connect(m_state_http, &mesos::set_state_json, 1))
	{
		throw sinsp_exception("Connection to Mesos API failed.");
	}
}
#endif // HAS_CAPTURE

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

void mesos::check_collector_status(int expected)
{
	if(!m_collector.is_healthy(expected))
	{
		throw sinsp_exception("Mesos collector not healthy (has " + std::to_string(m_collector.subscription_count()) +
							  " connections, expected " + std::to_string(expected) + "); giving up on data collection in this cycle ...");
	}
}

void mesos::send_data_request(bool collect)
{
	connect_mesos();
	send_mesos_data_request();
	if(!m_mesos_state_json.empty()) { return; }

	if(has_marathon())
	{
		connect_marathon();
		send_marathon_data_request();
		for(auto& group : m_marathon_groups_json)
		{
			if(!group.second.empty()) { return; }
		}
		for(auto& app : m_marathon_apps_json)
		{
			if(!app.second.empty()) { return; }
		}
	}

	if(collect) { collect_data(); }
}

void mesos::collect_data()
{
	//TODO: see if we can do better here - instead of timing out, depending on
	//      mesos_collector socket drop when remote end closes connection
	time_t now;
	time(&now);
	if(m_last_mesos_refresh && difftime(now, m_last_mesos_refresh) > 30)
	{
		throw sinsp_exception("Detected stalled Mesos connection (" +
							  std::to_string(difftime(now, m_last_mesos_refresh)) + "s)."
							  " Reconnect attempt in next cycle ...");
	}
	if(m_last_marathon_refresh && difftime(now, m_last_marathon_refresh) > 30)
	{
		throw sinsp_exception("Detected stalled Marathon connection(" +
							  std::to_string(difftime(now, m_last_marathon_refresh)) + "s)."
							  " Reconnect attempt in next cycle ...");
	}

	 m_collector.get_data();
	 if(!m_mesos_state_json.empty())
	 {
		if(has_marathon())
		{
			if(!m_marathon_apps_json.empty() && !m_marathon_groups_json.empty())
			{
				for(auto& group : m_marathon_groups_json)
				{
					if(group.second.size())
					{
						json_map_type_t::iterator app_it = m_marathon_apps_json.find(group.first);
						if(app_it != m_marathon_apps_json.end())
						{
							if(!app_it->second.empty())
							{
								if(!m_mesos_state_json.empty())
								{
									parse_state(std::move(m_mesos_state_json), "");
									m_mesos_state_json.clear();
									m_last_mesos_refresh = now;
								}
								g_logger.log("Collection detected " + std::to_string(m_inactive_frameworks.size()) + " inactive frameworks", sinsp_logger::SEV_DEBUG);
								if(m_inactive_frameworks.find(group.first) == m_inactive_frameworks.end())
								{
									g_logger.log("Detected active Marathon framework " + group.first, sinsp_logger::SEV_DEBUG);
									// +++ order is important - apps belong to groups and must be processed after
									parse_groups(std::move(group.second), group.first);
									parse_apps(std::move(app_it->second), app_it->first);
									m_last_marathon_refresh = now;
									// ---
								}
								else // framework was shut down, clear groups/apps
								{
									g_logger.log("Detected inactive Marathon framework " + group.first, sinsp_logger::SEV_DEBUG);
									m_state.erase_groups(group.first); // apps will go away with groups
									m_inactive_frameworks.insert(group.first);
								}
								group.second.clear();
								app_it->second.clear();
							}
						}
						else
						{
							// must never happen
							throw sinsp_exception("A discrepancy found between groups and apps "
												  "(app json for framework [" + group.first + "] not found in json map).");
						}
					}
				}
			}
		}
		else
		{
			if(!m_mesos_state_json.empty())
			{
				parse_state(std::move(m_mesos_state_json), "");
				m_mesos_state_json.clear();
				m_marathon_groups_json.clear();
				m_marathon_apps_json.clear();
				if(m_state_http->get_marathon_uris().size())
				{
					rebuild_marathon_state(true);
				}
			}
		}
	}
}
	
#endif // HAS_CAPTURE

void mesos::handle_frameworks(const Json::Value& root)
{
	bool do_init = false;
	const Json::Value& frameworks = root["frameworks"];
	if(!frameworks.isNull())
	{
		if(frameworks.isArray())
		{
			if(frameworks.size())
			{
				for(const auto& framework : frameworks)
				{
					const Json::Value& uid = framework["id"];
					if(!uid.isNull() && uid.isString())
					{
						const Json::Value& fw_name = framework["name"];
						std::string name;
						if(!fw_name.isNull() && fw_name.isString())
						{
							name = framework["name"].asString();
						}
						if(!mesos_framework::is_framework_active(framework))
						{
							framework_list_t::iterator it = m_inactive_frameworks.find(uid.asString());
							if(it == m_inactive_frameworks.end())
							{
								m_inactive_frameworks.insert(uid.asString());
								m_activated_frameworks.erase(uid.asString());
								g_logger.log("Mesos framework deactivated: " + name + '[' + uid.asString() + ']', sinsp_logger::SEV_INFO);
							}
						}
						else // active framework detected
						{
							if(m_inactive_frameworks.erase(uid.asString()))
							{
								g_logger.log("Activated Mesos framework detected: " + name + " [" + uid.asString() + ']', sinsp_logger::SEV_INFO);
								m_activated_frameworks.insert(uid.asString());
								do_init = true;
							}
							else
							{
								if(m_activated_frameworks.find(uid.asString()) == m_activated_frameworks.end())
								{
									m_activated_frameworks.insert(uid.asString());
									g_logger.log("New Mesos framework detected: " + name + " [" + uid.asString() + ']', sinsp_logger::SEV_INFO);
									do_init = true;
								}
							}
						}
					}
					if(!do_init) { add_framework(framework); }
				}
				if(do_init) { init(); }
			}
			else
			{
				if(has_marathon())
				{
					throw sinsp_exception("No Mesos frameworks found (possibly Mesos master HA migration, will retry).");
				}
				else
				{
					g_logger.log("No Mesos frameworks found.", sinsp_logger::SEV_INFO);
				}
			}
		}
		else
		{
			throw sinsp_exception("Mesos frameworks entry found but not a JSON array.");
		}
	}
	else
	{
		throw sinsp_exception("No Mesos frameworks entry found in state.");
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

void mesos::remove_framework(const Json::Value& framework)
{
	m_state.remove_framework(framework);
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
			if(mesos_task::is_task_running(task))
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

void mesos::check_frameworks(const std::string& json)
{
	if(has_marathon())
	{
		Json::Value root;
		Json::Reader reader;
		if(reader.parse(json, root, false))
		{
			Json::Value frameworks = root["frameworks"];
			if(frameworks.isNull())
			{
				throw sinsp_exception("No Mesos frameworks entry found.");
			}
			else
			{
				if(frameworks.isArray())
				{
					if(!frameworks.size())
					{
						throw sinsp_exception("No Mesos frameworks found (possibly Mesos master HA migration).");
					}
				}
				else
				{
					throw sinsp_exception("Unexpected Mesos frameworks entry found (not an array).");
				}
			}
		}
	}
}

void mesos::set_state_json(std::string&& json, const std::string&)
{
	if(!json.empty())
	{
		g_logger.log("Received state JSON " + std::to_string(json.size()), sinsp_logger::SEV_DEBUG);
		check_frameworks(json);
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
		g_logger.log("Received groups JSON (" + std::to_string(json.size()) + " bytes) for framework [" + framework_id + ']', sinsp_logger::SEV_DEBUG);
		m_marathon_groups_json[framework_id] = std::move(json);
	}
	else
	{
		g_logger.log("Received empty groups JSON", sinsp_logger::SEV_WARNING);
	}
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
