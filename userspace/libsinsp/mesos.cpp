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
const std::string mesos::default_state_api    = "/master/state.json";
const std::string mesos::default_marathon_uri = "http://localhost:8080";
const std::string mesos::default_groups_api   = "/v2/groups";
const std::string mesos::default_apps_api     = "/v2/apps?embed=apps.tasks";
const std::string mesos::default_watch_api    = "/v2/events";
const int mesos::default_timeout_ms           = 5000;

mesos::mesos(const std::string& state_uri,
	const std::string& state_api,
	const uri_list_t& marathon_uris,
	const std::string& groups_api,
	const std::string& apps_api,
	bool discover_mesos_leader,
	int timeout_ms,
	bool is_captured,
	bool verbose):
#ifdef HAS_CAPTURE
		m_collector(false),
		m_mesos_uri(state_uri),
		m_marathon_uris(marathon_uris),
#endif // HAS_CAPTURE
		m_state(is_captured, verbose),
		m_discover_mesos_leader(discover_mesos_leader),
		m_timeout_ms(timeout_ms),
		m_verbose(verbose)
{
	g_logger.log(std::string("Creating Mesos object for [" +
							 (m_mesos_uri.empty() ? std::string("capture replay") : m_mesos_uri)  +
							 "], failover autodiscovery set to ") +
							(m_discover_mesos_leader ? "true" : "false"),
				 sinsp_logger::SEV_DEBUG);
	init();
}

mesos::~mesos()
{
}

void mesos::init()
{
#ifdef HAS_CAPTURE
	if(!m_mesos_uri.empty())
	{
		m_collector.remove_all();
		if((m_state_http) && (!m_state_http.unique()))
		{
			throw sinsp_exception("Invalid access to Mesos initializer: mesos state http client for [" +
								 m_mesos_uri + "] not unique.");
		}
		m_state_http = std::make_shared<mesos_http>(*this, m_mesos_uri + default_state_api, m_discover_mesos_leader, m_timeout_ms);
		rebuild_mesos_state(true);
		init_marathon();
	}
#endif // HAS_CAPTURE
}

void mesos::init_marathon()
{
#ifdef HAS_CAPTURE
	if(!m_mesos_uri.empty())
	{
		m_marathon_groups_http.clear();
		m_marathon_apps_http.clear();

		const uri_list_t& marathons = m_marathon_uris.size() ? m_marathon_uris : m_state_http->get_marathon_uris();
		for(const auto& muri : marathons)
		{
			m_marathon_groups_http[muri] = std::make_shared<marathon_http>(*this, muri + default_groups_api, m_timeout_ms);
			m_marathon_apps_http[muri]   = std::make_shared<marathon_http>(*this, muri + default_apps_api, m_timeout_ms);
		}

		if(has_marathon())
		{
			rebuild_marathon_state(true);
		}
	}
#endif // HAS_CAPTURE
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
	if(!m_mesos_uri.empty())
	{
		if(full)
		{
			clear_mesos();
			if(m_state_http)
			{
				m_state_http->get_all_data(&mesos::parse_state);
			}
			else
			{
				throw sinsp_exception("Mesos state HTTP client is null.");
			}
		}
		else
		{
			connect_mesos();
			send_mesos_data_request();
			collect_data();
		}
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
				if(group_http.second)
				{
					group_http.second->get_all_data(&mesos::parse_groups);
				}
				else
				{
					throw sinsp_exception("Marathon groups HTTP client is null.");
				}
			}

			for(auto& app_http : m_marathon_apps_http)
			{
				if(app_http.second)
				{
					app_http.second->get_all_data(&mesos::parse_apps);
				}
				else
				{
					throw sinsp_exception("Marathon apps HTTP client is null.");
				}
			}
		}
		else
		{
			connect_marathon();
			send_marathon_data_request();
			collect_data();
		}
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
			if(group_http.second)
			{
				group_http.second->send_request();
			}
			else
			{
				throw sinsp_exception("Marathon groups HTTP client is null.");
			}
		}
		for(auto& app_http : m_marathon_apps_http)
		{
			if(app_http.second)
			{
				app_http.second->send_request();
			}
			else
			{
				throw sinsp_exception("Marathon apps HTTP client is null.");
			}
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
	if(m_state_http)
	{
		m_state_http->send_request();
	}
	else
	{
		throw sinsp_exception("Mesos state HTTP client is null.");
	}
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
	if(m_state_http && !m_state_http->is_connected())
	{
		g_logger.log("Mesos state connection loss.", sinsp_logger::SEV_WARNING);
		return false;
	}

	for(const auto& group : m_marathon_groups_http)
	{
		if(group.second && !group.second->is_connected())
		{
			g_logger.log("Marathon groups connection loss.", sinsp_logger::SEV_WARNING);
			return false;
		}
	}

	for(const auto& app : m_marathon_apps_http)
	{
		if(app.second && !app.second->is_connected())
		{
			g_logger.log("Marathon apps connection loss.", sinsp_logger::SEV_WARNING);
			return false;
		}
	}
#endif // HAS_CAPTURE
	return true;
}

#ifdef HAS_CAPTURE

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
	if(!m_mesos_state_json.empty()) { return; }
	connect_mesos();
	send_mesos_data_request();
	g_logger.log("Mesos request sent.", sinsp_logger::SEV_DEBUG);

	if(has_marathon())
	{
		for(auto& group : m_marathon_groups_json)
		{
			if(!group.second.empty()) { return; }
			g_logger.log("Marathon groups request sent.", sinsp_logger::SEV_DEBUG);
		}
		for(auto& app : m_marathon_apps_json)
		{
			if(!app.second.empty()) { return; }
			g_logger.log("Marathon apps request sent.", sinsp_logger::SEV_DEBUG);
		}
		connect_marathon();
		send_marathon_data_request();
	}

	if(collect) { collect_data(); }
}

bool mesos::collect_data()
{
	//TODO: see if we can do better here - instead of timing out, depending on
	//      mesos_collector socket drop detection when remote end closes connection
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
	if(m_json_error)
	{
		throw sinsp_exception("Detected JSON parsing error. Reconnect attempt in next cycle ...");
	}

	bool ret = false;
	if(m_collector.subscription_count())
	{
		m_collector.get_data();
		if(!m_mesos_state_json.empty())
		{
			g_logger.log("Mesos state data detected.", sinsp_logger::SEV_DEBUG);
			if(has_marathon())
			{
				g_logger.log("Marathon connection detected.", sinsp_logger::SEV_DEBUG);
				if(!m_marathon_apps_json.empty() && !m_marathon_groups_json.empty())
				{
					g_logger.log("Marathon data detected.", sinsp_logger::SEV_DEBUG);
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
										parse_state(std::move(m_mesos_state_json), std::string());
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
									ret = true;
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
				parse_state(std::move(m_mesos_state_json), std::string());
				m_mesos_state_json.clear();
				m_marathon_groups_json.clear();
				m_marathon_apps_json.clear();
				if(m_state_http->get_marathon_uris().size())
				{
					rebuild_marathon_state(true);
				}
				ret = true;
			}
		}
	}

	return ret;
}

void mesos::capture_frameworks(const Json::Value& root, Json::Value& capture)
{
	const Json::Value& frameworks = root["frameworks"];
	if(!frameworks.isNull())
	{
		if(frameworks.isArray())
		{
			if(frameworks.size())
			{
				capture["frameworks"] = Json::arrayValue;
				for(const auto& framework : frameworks)
				{
					Json::Value c_framework;
					c_framework["active"] = framework["active"];
					c_framework["id"] = framework["id"];
					c_framework["name"] = framework["name"];
					c_framework["hostname"] = framework["hostname"];
					c_framework["webui_url"] = framework["webui_url"];
					c_framework["tasks"] = Json::arrayValue;
					Json::Value& c_tasks = c_framework["tasks"];
					for(const auto& task : framework["tasks"])
					{
						Json::Value& c_task = c_tasks.append(Json::Value());
						c_task["id"] = task["id"];
						c_task["name"] = task["name"];
						c_task["framework_id"] = task["framework_id"];
						c_task["executor_id"] = task["executor_id"];
						c_task["slave_id"] = task["slave_id"];
						c_task["state"] = task["state"];
						//? TODO: statuses
						c_task["labels"] = task["labels"];
					}
					capture["frameworks"].append(c_framework);
				}
			}
		}
	}
}

void mesos::capture_slaves(const Json::Value& root, Json::Value& capture)
{
	const Json::Value& slaves = root["slaves"];
	if(!slaves.isNull())
	{
		capture["slaves"] = Json::arrayValue;
		for(const auto& slave : slaves)
		{
			Json::Value c_slave;
			c_slave["hostname"] = slave["hostname"];
			c_slave["id"] = slave["id"];
			capture["slaves"].append(c_slave);
		}
	}
}
#endif // HAS_CAPTURE

void mesos::handle_frameworks(const Json::Value& root)
{
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
								std::string fid = uid.asString();
								m_inactive_frameworks.insert(fid);
								m_activated_frameworks.erase(fid);
								g_logger.log("Mesos framework deactivated: " + name + '[' + fid + ']', sinsp_logger::SEV_INFO);
								remove_framework(framework);
#ifdef HAS_CAPTURE
								remove_framework_http(m_marathon_groups_http, fid);
								remove_framework_http(m_marathon_apps_http, fid);
#endif // HAS_CAPTURE
							}
						}
						else // active framework detected
						{
							add_framework(framework);
							if((m_inactive_frameworks.erase(uid.asString())) ||
							   (m_activated_frameworks.find(uid.asString()) == m_activated_frameworks.end()))
							{
								g_logger.log("New or activated Mesos framework detected: " + name + " [" + uid.asString() + ']', sinsp_logger::SEV_INFO);
								m_activated_frameworks.insert(uid.asString());
								if(mesos_framework::is_marathon(name))
								{
									init_marathon();
								}
							}
						}
					}
				}
			}
			else
			{
				throw sinsp_exception("No Mesos frameworks found (possibly Mesos master HA migration, will retry).");
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
	const Json::Value& slaves = root["slaves"];
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

#ifdef HAS_CAPTURE
void mesos::remove_framework_http(marathon_http_map& http_map, const std::string& framework_id)
{
	for(marathon_http_map::iterator it = http_map.begin(), end = http_map.end(); it != end; ++it)
	{
		if(it->second && it->second->get_framework_id() == framework_id)
		{
			http_map.erase(it);
			g_logger.log("Removed http for deactivated Marathon framework [" + framework_id + ']',
						 sinsp_logger::SEV_DEBUG);
			return;
		}
	}
}
#endif // HAS_CAPTURE

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
	const Json::Value& tasks = f_val["tasks"];
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
		g_logger.log("Received state JSON", sinsp_logger::SEV_DEBUG);
		//g_logger.log('<' + json + '>', sinsp_logger::SEV_DEBUG);
		check_frameworks(json);
		m_mesos_state_json = std::move(json);
	}
	else
	{
		g_logger.log("Received empty state JSON", sinsp_logger::SEV_WARNING);
		m_json_error = true;
	}
}

void mesos::parse_state(Json::Value&& root, bool discover_uris)
{
	clear_mesos();
#ifdef HAS_CAPTURE
	if(discover_uris && !has_marathon())
	{
		m_state_http->discover_framework_uris(root["frameworks"]);
		if(has_marathon())
		{
			init_marathon();
		}
	}
#endif // HAS_CAPTURE
	handle_frameworks(root);
	handle_slaves(root);
#ifdef HAS_CAPTURE
	if(m_state.is_captured())
	{
		Json::Value capt;
		capture_frameworks(root, capt);
		capture_slaves(root, capt);
		m_state.enqueue_capture_event(mesos_state_t::capture::MESOS_STATE, Json::FastWriter().write(capt));
	}
#endif // HAS_CAPTURE
	if(m_verbose)
	{
		std::cout << Json::FastWriter().write(root) << std::endl;
	}
	if(!m_creation_logged)
	{
		m_creation_logged = true;
	}
}

void mesos::parse_state(std::string&& json, const std::string&)
{
	Json::Value root;
	Json::Reader reader;
	if(reader.parse(json, root, false))
	{
		parse_state(std::move(root));
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
		//g_logger.log('<' + json + '>', sinsp_logger::SEV_DEBUG);
		m_marathon_groups_json[framework_id] = std::move(json);
	}
	else
	{
		g_logger.log("Received empty groups JSON", sinsp_logger::SEV_WARNING);
		m_json_error = true;
	}
}

void mesos::set_marathon_apps_json(std::string&& json, const std::string& framework_id)
{
	if(!json.empty())
	{
		g_logger.log("Received apps JSON (" + std::to_string(json.size()) + " bytes) for framework [" + framework_id + ']', sinsp_logger::SEV_DEBUG);
		//g_logger.log('<' + json + '>', sinsp_logger::SEV_DEBUG);
		m_marathon_apps_json[framework_id] = std::move(json);
	}
	else
	{
		g_logger.log("Received empty apps JSON", sinsp_logger::SEV_WARNING);
		m_json_error = true;
	}
}

void mesos::simulate_event(const std::string& json)
{
	Json::Value root;
	Json::Reader reader;
	if(reader.parse(json, root))
	{
		Json::Value::Members members = root.getMemberNames();
		for (auto& member : members)
		{
			if(member == "mesos_state")
			{
				parse_state(std::move(root[member]), false);
			}
			else if(member == "marathon_groups")
			{
				const Json::Value& frameworkId = root[member]["frameworkId"];
				if(!frameworkId.isNull() && frameworkId.isString())
				{
					m_state.parse_groups(std::move(root[member]), frameworkId.asString());
				}
				else
				{
					throw sinsp_exception("Framework ID for Marathon groups not found during event simulation.");
				}
			}
			else if(member == "marathon_apps")
			{
				const Json::Value& frameworkId = root[member]["frameworkId"];
				if(!frameworkId.isNull() && frameworkId.isString())
				{
					m_state.parse_apps(std::move(root[member]), frameworkId.asString());
				}
				else
				{
					throw sinsp_exception("Framework ID for Marathon groups not found during event simulation.");
				}
			}
		}
	}
}
