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
	const std::string& watch_api): m_state_http(*this, state_uri + state_api),
		m_collector(false)
{
	for(const auto& uri : marathon_uris)
	{
		int port = (uri.substr(0, 5) == "https") ? 443 : 80;
		std::string::size_type pos = uri.rfind(':');
		if(pos != std::string::npos)
		{
			std::string::size_type ppos = uri.find('/', pos);
			if(ppos == std::string::npos)
			{
				ppos = pos + (uri.length() - pos);
			}
			ASSERT(ppos - (pos + 1) > 0);
			port = std::stoi(uri.substr(pos + 1, ppos - (pos + 1)));
		}
		m_marathon_groups_http[port] = std::make_shared<marathon_http>(*this, uri + groups_api, true);
		m_marathon_apps_http[port]   = std::make_shared<marathon_http>(*this, uri + apps_api, true);
		m_marathon_watch_http[port]  = std::make_shared<marathon_http>(*this, uri + watch_api, true);
		m_dispatch[port]             = std::make_shared<marathon_dispatcher>(m_state, m_marathon_watch_http[port]->get_id());
	}

	refresh(marathon_uris.size());
}

mesos::~mesos()
{
}

void mesos::refresh(bool marathon)
{
	clear(marathon);

	m_state_http.get_all_data(&mesos::parse_state);

	if(marathon)
	{
		for(auto& app_http : m_marathon_apps_http)
		{
			app_http.second->get_all_data(&mesos::parse_apps);
		}

		for(auto& group_http : m_marathon_groups_http)
		{
			group_http.second->get_all_data(&mesos::parse_groups);
		}

		for(auto watch_http : m_marathon_watch_http)
		{
			m_collector.add(watch_http.second);
		}
	}
}

bool mesos::is_alive() const
{
	bool connected = true;

	connected &= m_state_http.is_connected();
	for(const auto& group : m_marathon_groups_http)
	{
		connected &= group.second->is_connected();
	}

	for(const auto& app : m_marathon_apps_http)
	{
		connected &= app.second->is_connected();
	}

	connected &= (m_collector.subscription_count() > 0);

	return connected;
}

void mesos::watch()
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

void mesos::determine_node_type(const Json::Value& root)
{
	Json::Value flags = root["flags"];
	if(!flags.isNull())
	{
		Json::Value port = flags["port"];
		if(!port.isNull())
		{
			if(port.asString() == "5050")
			{
				m_node_type = NODE_MASTER;
			}
			else if(port.asString() == "5051")
			{
				m_node_type = NODE_SLAVE;
			}
			else
			{
				throw sinsp_exception("Can not determine node type");
			}
		}
	}
}

void mesos::add_task_labels(std::string& json)
{
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
						Json::Value labels = m_state_http.get_task_labels(root["taskId"].asString());
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
}

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
	// if this is marathon task status update, we need to get the labels
	// from mesos because the update message does not contain them
	// TODO (maybe): refactor to keep labels in apps and have tasks labels updated
	// when tasks are asigned to apps
	add_task_labels(msg.get_data());

	// if this is group change, replace event data (which does not contain enough
	// information to rebuild state) with Marathon state API JSON
	for(auto& http : m_marathon_groups_http)
	{
		if(http.second->get_id() == framework_id)
		{
			get_groups(http.second, msg.get_data());
		}
	}

	for(auto& dispatcher : m_dispatch)
	{
		if(framework_id == dispatcher.second->get_id())
		{
			dispatcher.second->enqueue(std::move(msg));
			break;
		}
	}
}

void mesos::parse_state(const std::string& json)
{
	Json::Value root;
	Json::Reader reader;
	if(reader.parse(json, root, false))
	{
		//g_logger.log(root.toStyledString(), sinsp_logger::SEV_DEBUG);
		determine_node_type(root);
		handle_frameworks(root);
		handle_slaves(root);
	}
	else
	{
		throw sinsp_exception("Invalid JSON (parsing Mesos state failed).");
	}
}

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
	std::ostringstream os;
	os << "Adding Mesos framework: [" << name << ',' << uid << ']';
	g_logger.log(os.str(), sinsp_logger::SEV_INFO);
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
	std::ostringstream os;
	os << "Adding Mesos slave: [" << name << ',' << uid << ']';
	g_logger.log(os.str(), sinsp_logger::SEV_INFO);
	m_state.emplace_slave(mesos_slave(name, uid));
}

void mesos::add_tasks_impl(mesos_framework& framework, const Json::Value& tasks)
{
	if(!tasks.isNull())
	{
		for(const auto& task : tasks)
		{
			std::string name, uid, sid;
			Json::Value fname = task["name"];
			if(!fname.isNull()) { name = fname.asString(); }
			Json::Value fid = task["id"];
			if(!fid.isNull()) { uid = fid.asString(); }
			Json::Value fsid = task["slave_id"];
			if(!fsid.isNull()) { sid = fsid.asString(); }

			std::ostringstream os;
			os << "Adding Mesos task: [" << framework.get_name() << ':' << name << ',' << uid << ']';
			g_logger.log(os.str(), sinsp_logger::SEV_DEBUG);
			std::shared_ptr<mesos_task> t(new mesos_task(name, uid));
			t->set_slave_id(sid);
			add_labels(t, task);
			m_state.add_or_replace_task(framework, t);
		}
	}
	else
	{
		g_logger.log("tasks is null", sinsp_logger::SEV_DEBUG);
	}
}

void mesos::add_tasks(mesos_framework& framework, const Json::Value& f_val)
{
	if(is_master())
	{
		Json::Value tasks = f_val["tasks"];
		add_tasks_impl(framework, tasks);
	}
	else
	{
		Json::Value executors = f_val["executors"];
		if(!executors.isNull())
		{
			for(const auto& executor : executors)
			{
				Json::Value tasks = executor["tasks"];
				add_tasks_impl(framework, tasks);
			}
		}
	}
}

void mesos::add_labels(std::shared_ptr<mesos_task> task, const Json::Value& t_val)
{
	Json::Value labels = t_val["labels"];
	if(!labels.isNull())
	{
		for(const auto& label : labels)
		{
			std::string key, val;
			Json::Value lkey = label["key"];
			Json::Value lval = label["value"];
			if(!lkey.isNull())
			{
				key = lkey.asString();
			}
			if(!lval.isNull())
			{
				val = lval.asString();
			}
			std::ostringstream os;
			os << "Adding Mesos task label: [" << key << ':' << val << ']';
			g_logger.log(os.str(), sinsp_logger::SEV_DEBUG);
			task->emplace_label(mesos_pair_t(key, val));
		}
	}
}

void mesos::parse_groups(const std::string& json)
{
	m_state.parse_groups(json);
}

void mesos::parse_apps(const std::string& json)
{
	m_state.parse_apps(json);
}
