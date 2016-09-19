//
// k8s_handler.cpp
//

#include "k8s_handler.h"
#include "sinsp.h"
#include "sinsp_int.h"

// to match regular K8s API message format,
// error is wrapped into a single-entry array
std::string k8s_handler::ERROR_FILTER =
	"{ type: \"ERROR\","
	"  apiVersion: .apiVersion,"
	"  kind: .kind,"
	"  items:"
	"  ["
	"   . |"
	"   {"
	"     metadata: .metadata,"
	"     status: .status,"
	"     message: .message,"
	"     reason: .reason,"
	"     details: .details,"
	"     code: .code"
	"   }"
	"  ]"
	"}";

k8s_handler::k8s_handler(const std::string& id,
	bool is_captured,
	std::string url,
	const std::string& path,
	const std::string& state_filter,
	const std::string& event_filter,
	collector_ptr_t collector,
	const std::string& http_version,
	int timeout_ms,
	ssl_ptr_t ssl,
	bt_ptr_t bt,
	k8s_state_t* state,
	bool watch,
	bool connect): m_state(state),
		m_collector(collector),
		m_id(id + "_state"),
		m_path(path),
		m_state_filter(state_filter),
		m_event_filter(event_filter),
		m_filter(m_state_filter),
		m_timeout_ms(timeout_ms),
		m_url(url),
		m_http_version(http_version),
		m_ssl(ssl),
		m_bt(bt),
		m_watch(watch),
		m_connect(connect),
		m_is_captured(is_captured)
{
	g_logger.log("Creating K8s " + name() + " (" + m_id + ") "
				 "handler object for [" + m_url + m_path + ']',
				 sinsp_logger::SEV_DEBUG);
	make_http();
}

k8s_handler::~k8s_handler()
{
}

void k8s_handler::make_http()
{
	if(m_connect)
	{
		m_http = std::make_shared<handler_t>(*this, m_id,
									 m_url, m_path, m_http_version,
									 m_timeout_ms, m_ssl, m_bt);
		m_http->set_json_callback(&k8s_handler::set_event_json);
		m_http->set_json_end("}\n");
		m_http->add_json_filter(m_filter);
		m_http->add_json_filter(ERROR_FILTER);
		connect();
	}
}

void k8s_handler::check_enabled()
{
	if(!m_http->is_enabled())
	{
		g_logger.log("k8s_handler (" + m_id +
					") connect() enabling socket in collector", sinsp_logger::SEV_TRACE);
		m_http->enable();
	}
	else
	{
		g_logger.log("k8s_handler (" + m_id +
					") connect() socket in collector is enabled, "
					"checking collector status.", sinsp_logger::SEV_TRACE);
		check_collector_status();
	}
}

bool k8s_handler::connect()
{
	if(m_collector && m_http)
	{
		if(!m_collector->has(m_http))
		{
			g_logger.log(std::string("k8s_handler (" + m_id +
									 ") connect() adding socket to collector"), sinsp_logger::SEV_TRACE);
			m_collector->add(m_http);
			return false;
		}
		if(m_http->is_connecting())
		{
			g_logger.log(std::string("k8s_handler (" + m_id +
									 "), connect() connecting to " + m_url), sinsp_logger::SEV_TRACE);
			return false;
		}
		if(m_http->is_connected())
		{
			g_logger.log("k8s_handler (" + m_id +
						") connect() socket is connected.", sinsp_logger::SEV_TRACE);
			check_enabled();
			return true;
		}
	}
	else if (!m_url.empty())
	{
		g_logger.log(std::string("k8s_handler (" + m_id +
									 ") connect(), http is null, (re)creating ... "), sinsp_logger::SEV_WARNING);
		make_http();
	}
	return false;
}

void k8s_handler::send_data_request()
{
	if(m_http && !m_req_sent)
	{
		if(m_http->is_connected())
		{
			g_logger.log("k8s_handler (" + m_id + ") sending request to " + m_url,
						 sinsp_logger::SEV_DEBUG);
			m_http->send_request();
			m_req_sent = true;
		}
		else if(m_http->is_connecting())
		{
			g_logger.log("k8s_handler (" + m_id + ") is connecting to " + m_url,
						 sinsp_logger::SEV_DEBUG);
		}
	}
	else
	{
		throw sinsp_exception("k8s_handler (" + m_id + ") HTTP client (" + m_url + ") is null.");
	}
}

bool k8s_handler::is_alive() const
{
	if(m_http && !m_http->is_connecting() && !m_http->is_connected())
	{
		g_logger.log("k8s_handler (" + m_id + ") state connection (" + m_url + ") loss.",
					 sinsp_logger::SEV_WARNING);
		return false;
	}
	return true;
}

void k8s_handler::check_collector_status()
{
	if(m_collector && !m_collector->is_healthy(m_http))
	{
		throw sinsp_exception("k8s_handler (" + m_id + ") collector not healthy, "
							  "giving up on data collection in this cycle ...");
	}
}

void k8s_handler::process_events()
{
	for(auto evt : m_events)
	{
		if(evt && !evt->isNull())
		{
			g_logger.log("k8s_handler (" + m_id + ") data:\n" + json_as_string(*evt),
				 sinsp_logger::SEV_TRACE);
			handle_json(std::move(*evt));

			if(m_is_captured)
			{
				m_state->enqueue_capture_event(*evt);
			}
		}
		else
		{
			g_logger.log("k8s_handler (" + m_id + ") error (" + m_url + ") " +
						(!evt ? "data is null." : (evt->isNull() ? "JSON is null." : "Unknown")),
						sinsp_logger::SEV_ERROR);
		}
	}
	m_events.clear();
}

void k8s_handler::check_state()
{
	if(m_collector && !m_state_built && m_watch)
	{
		// done with initial state handling, switch to events
		m_state_built = true;
		m_collector->remove(m_http);
		m_http.reset();
		std::string::size_type pos = m_id.find("_state");
		if(pos != std::string::npos)
		{
			m_id = m_id.substr(0, pos).append("_event");
		}
		pos = m_path.find("/watch");
		if(pos == std::string::npos)
		{
			pos = m_path.rfind('/');
			if(pos != std::string::npos)
			{
				m_path.insert(pos, "/watch");
			}
			else
			{
				throw sinsp_exception("k8s_handler (" + m_id + "), invalid URL path: " + m_url);
			}
		}
		m_filter = m_event_filter;
		m_req_sent = false;
		make_http();
	}
}

bool k8s_handler::connection_error() const
{
	if(m_http)
	{
		return m_http->connection_error();
	}
	return false;
}

void k8s_handler::collect_data()
{
	if(m_collector && m_http)
	{
		process_events(); // there may be leftovers from state connection closed by collector
		check_state(); // switch to events, if needed
		g_logger.log("k8s_handler (" + m_id + ") collect_data(), checking connection to " + m_url, sinsp_logger::SEV_DEBUG);
		if(m_http->is_connecting())
		{
			g_logger.log("k8s_handler (" + m_id + ") collect_data(), connecting to " + m_url, sinsp_logger::SEV_DEBUG);
			return;
		}
		else if(m_http->is_connected())
		{
			check_enabled();
			if(!m_req_sent)
			{
				g_logger.log("k8s_handler (" + m_id + ") collect_data(), connected to " + m_url + ", requesting data ...",
							 sinsp_logger::SEV_DEBUG);
				send_data_request();
			}
			if(m_collector->subscription_count())
			{
				g_logger.log("k8s_handler (" + m_id + ") collect_data(), connected to " + m_url + ", getting data ...",
							 sinsp_logger::SEV_DEBUG);
				m_collector->get_data();
				g_logger.log("k8s_handler (" + m_id + ") collect_data(), " + std::to_string(m_events.size()) + " events from " + m_url,
							 sinsp_logger::SEV_DEBUG);
				if(m_events.size())
				{
					g_logger.log("k8s_handler (" + m_id + ") collect_data(), data from " + m_url +
								 "event count=" + std::to_string(m_events.size()),
								 sinsp_logger::SEV_DEBUG);
					process_events();
					check_state();
				}
				else
				{
					g_logger.log("k8s_handler (" + m_id + ") collect_data(), no data from " + m_url,
							 sinsp_logger::SEV_DEBUG);
				}
			}
			return;
		}
		else
		{
			connect();
		}
		m_req_sent = false;
		g_logger.log("k8s_handler (" + m_id + "), http interface not (yet?) connected to " + m_url,
					 sinsp_logger::SEV_TRACE);
	}
	else
	{
		g_logger.log("k8s_handler (" + m_id + "), http interface not (yet?) created for " + m_url + ").",
					 sinsp_logger::SEV_TRACE);
	}
}

k8s_handler::msg_data k8s_handler::get_msg_data(const std::string& type, const std::string& kind, const Json::Value& json)
{
	msg_data data;
	if(!type.empty())
	{
		if(type[0] == 'A') { data.m_reason = k8s_component::COMPONENT_ADDED; }
		else if(type[0] == 'M') { data.m_reason = k8s_component::COMPONENT_MODIFIED; }
		else if(type[0] == 'D') { data.m_reason = k8s_component::COMPONENT_DELETED; }
		else if(type[0] == 'E') { data.m_reason = k8s_component::COMPONENT_ERROR; }
	}
	else
	{
		return data;
	}

	data.m_kind = kind;

	Json::Value name = json["name"];
	if(!name.isNull())
	{
		data.m_name = name.asString();
	}
	Json::Value uid = json["uid"];
	if(!uid.isNull())
	{
		data.m_uid = uid.asString();
	}
	Json::Value nspace = json["namespace"];
	if(!nspace.isNull())
	{
		data.m_namespace = nspace.asString();
	}

	return data;
}

void k8s_handler::handle_json(Json::Value&& root)
{
	/*if(g_logger.get_severity() >= sinsp_logger::SEV_TRACE)
	{
		g_logger.log(json_as_string(root), sinsp_logger::SEV_TRACE);
	}*/

	if(!m_state)
	{
		throw sinsp_exception("k8s_handler (" + m_id + "), state is null for " + m_url + ").");
	}
	const Json::Value& type = root["type"];
	if(!type.isNull())
	{
		if(type.isConvertibleTo(Json::stringValue))
		{
			const Json::Value& kind = root["kind"];
			if(!kind.isNull())
			{
				if(kind.isConvertibleTo(Json::stringValue))
				{
					std::string t = type.asString();
					std::string k = kind.asString();
					for(const Json::Value& item : root["items"])
					{
						msg_data data = get_msg_data(t, k, item);
						/*
						  uncomment to test proper error handling

						//if(name() == "replicasets") // vary name to verify (non)critical component error handling
						if(name() == "pods")
						{
							std::string j = "{"
											" \"metadata\": \"{}\","
											" \"status\": \"Failure\","
											" \"message\": \"the server could not find the requested resource\","
											" \"reason\": \"NotFound\","
											" \"details\": \"{}\","
											" \"code\": 404"
											"}";
							Json::Value i;
							Json::Reader().parse(j, i);
							data.m_reason = k8s_component::COMPONENT_ERROR;
							handle_error(data, i);
							continue;
						}
						*/
						std::string reason_type = data.get_reason_desc();
						if(data.m_reason == k8s_component::COMPONENT_ADDED)
						{
							if(m_state->has(data.m_uid))
							{
								std::ostringstream os;
								os << "K8s " + reason_type + " message received for existing " << data.m_kind <<
									" [" << data.m_uid << "], updating only.";
								g_logger.log(os.str(), sinsp_logger::SEV_WARNING);
							}
						}
						else if(data.m_reason == k8s_component::COMPONENT_MODIFIED)
						{
							if(!m_state->has(data.m_uid))
							{
								std::ostringstream os;
								os << "K8s " + reason_type + " message received for non-existing " << data.m_kind <<
									" [" << data.m_uid << "], giving up.";
								g_logger.log(os.str(), sinsp_logger::SEV_WARNING);
								continue;
							}
						}
						else if(data.m_reason == k8s_component::COMPONENT_DELETED)
						{
							if(!m_state->has(data.m_uid))
							{
								std::ostringstream os;
								os << "K8s " + reason_type + " message received for non-existing " << data.m_kind <<
									" [" << data.m_uid << "], giving up.";
								g_logger.log(os.str(), sinsp_logger::SEV_ERROR);
								continue;
							}
						}
						else if(data.m_reason == k8s_component::COMPONENT_ERROR)
						{
							handle_error(data, item);
							continue;
						}
						else
						{
							g_logger.log(std::string("Unsupported K8S " + name() + " event reason: ") +
										 std::to_string(data.m_reason), sinsp_logger::SEV_ERROR);
							continue;
						}
						/*if(g_logger.get_severity() >= sinsp_logger::SEV_TRACE)
						{
							g_logger.log("K8s handling item:\n" + json_as_string(item), sinsp_logger::SEV_TRACE);
						}*/
						if(handle_component(item, &data))
						{
							std::ostringstream os;
							os << "K8s [" + reason_type + ", " << data.m_kind <<
								", " << data.m_name << ", " << data.m_uid << "]";
							g_logger.log(os.str(), sinsp_logger::SEV_INFO);
							m_state->update_cache(k8s_component::get_type(name()));
						}
						else
						{
							g_logger.log("K8s: error occurred while handling " + reason_type +
										 " event for " + data.m_kind + ' ' + data.m_name + " [" +
										 data.m_uid + ']', sinsp_logger::SEV_ERROR);
						}
					} // end for nodes
				}
			}
		}
		else
		{
			g_logger.log(std::string("K8S event type is not string."), sinsp_logger::SEV_ERROR);
		}
	}
	else
	{
		g_logger.log(std::string("K8S event type is null."), sinsp_logger::SEV_ERROR);
	}
}

bool k8s_handler::is_ip_address(const std::string& addr)
{
	struct sockaddr_in serv_addr = {0};
	return inet_aton(addr.c_str(), &serv_addr.sin_addr);
}

k8s_handler::ip_addr_list_t k8s_handler::hostname_to_ip(const std::string& hostname)
{
	ip_addr_list_t ip_addrs;
	struct addrinfo *servinfo = 0;

	struct addrinfo hints = {0};
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if((getaddrinfo(hostname.c_str(), NULL, &hints, &servinfo)) != 0)
	{
		g_logger.log("Can't determine IP address for hostname: " + hostname, sinsp_logger::SEV_WARNING);
		return ip_addrs;
	}

	for(struct addrinfo* p = servinfo; p != NULL; p = p->ai_next)
	{
		struct sockaddr_in* h = (struct sockaddr_in*)p->ai_addr;
		ip_addrs.emplace(inet_ntoa(h->sin_addr));
	}

	freeaddrinfo(servinfo);
	return ip_addrs;
}

void k8s_handler::set_event_json(json_ptr_t json, const std::string&)
{
	g_logger.log("k8s_handler adding event, (" + m_id + ") has " + std::to_string(m_events.size()) +
				 " events from " + m_url, sinsp_logger::SEV_TRACE);
	if(json)
	{
		m_events.emplace_back(json);
		g_logger.log("k8s_handler added event, (" + m_id + ") has " + std::to_string(m_events.size()) +
					 " events from " + m_url, sinsp_logger::SEV_TRACE);
	}
	else
	{
		g_logger.log("K8s: delegator (" + m_id + ") received null JSON", sinsp_logger::SEV_ERROR);
	}
}

k8s_pair_list k8s_handler::extract_object(const Json::Value& object)
{
	k8s_pair_list entry_list;
	if(!object.isNull() && object.isObject())
	{
		Json::Value::Members members = object.getMemberNames();
		for (auto& member : members)
		{
			const Json::Value& val = object[member];
			if(!val.isNull() && val.isString())
			{
				entry_list.emplace_back(k8s_pair_t(member, val.asString()));
			}
		}
	}
	return entry_list;
}

std::string k8s_handler::name() const
{
	std::string n;
	std::string::size_type slash_pos = m_path.rfind('/');
	std::string::size_type qm_pos = m_path.rfind('?');
	std::string::size_type length =
		(qm_pos == std::string::npos) ?
		 std::string::npos : qm_pos - slash_pos - 1;

	if((slash_pos != std::string::npos) && (++slash_pos < m_path.size()))
	{
		n = m_path.substr(slash_pos, length);
	}

	return n;
}

void k8s_handler::handle_error(const msg_data& data, const Json::Value& root, bool log)
{
	if(log)
	{
		log_error(data, root);
	}
}

void k8s_handler::log_error(const msg_data& data, const Json::Value& json)
{
	std::string unk_err = "Unknown.";
	std::ostringstream os;;
	os << "K8S server reported " << name() << " error for [" + m_url + m_path + "]: ";
	if(!json.isNull())
	{
		os << std::endl << json.toStyledString();
		unk_err.clear();
		m_error.reset(new k8s_api_error(data, json));
	}
	os << unk_err;
	g_logger.log(os.str(), sinsp_logger::SEV_ERROR);
}
