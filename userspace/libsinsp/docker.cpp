/*
Copyright (C) 2013-2018 Draios Inc dba Sysdig.

This file is part of sysdig.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/
//
// docker.cpp
//

#if defined(__linux__)

#include "sinsp.h"
#include "sinsp_int.h"
#include "docker.h"
#include "user_event.h"

const std::string docker::DOCKER_SOCKET_FILE = "/var/run/docker.sock";
#ifdef HAS_CAPTURE
int docker::m_connection_id = 0;
bool docker::m_ever_connected = false;
#endif

docker::docker(std::string url,
	const std::string& path,
	const std::string& http_version,
	int timeout_ms,
	bool is_captured,
	bool verbose,
	event_filter_ptr_t event_filter): m_id("docker"),
		m_timeout_ms(timeout_ms),
		m_is_captured(is_captured),
		m_verbose(verbose),
		m_event_filter(event_filter),
		m_container_events{"attach", "commit", "copy", "create",
							"destroy", "die", "exec_create", "exec_start",
							"export", "kill", "oom", "pause", "rename", "resize",
							"restart", "start", "stop", "top", "unpause", "update"},
		m_image_events{"delete", "import", "pull", "push", "tag", "untag"},
		m_volume_events{"create", "mount", "unmount", "destroy"},
		m_network_events{"create", "connect", "disconnect", "destroy"},
		m_severity_map
		{
			// container
			{ "attach",      sinsp_logger::SEV_EVT_INFORMATION },
			{ "archive-path", sinsp_logger::SEV_EVT_INFORMATION },
			{ "commit",      sinsp_logger::SEV_EVT_INFORMATION },
			{ "copy",        sinsp_logger::SEV_EVT_INFORMATION },
			{ "create",      sinsp_logger::SEV_EVT_INFORMATION },
			{ "destroy",     sinsp_logger::SEV_EVT_WARNING     },
			{ "die",         sinsp_logger::SEV_EVT_WARNING     },
			{ "exec_create", sinsp_logger::SEV_EVT_INFORMATION },
			{ "exec_start",  sinsp_logger::SEV_EVT_INFORMATION },
			{ "export",      sinsp_logger::SEV_EVT_INFORMATION },
			{ "kill",        sinsp_logger::SEV_EVT_WARNING     },
			{ "oom",         sinsp_logger::SEV_EVT_WARNING     },
			{ "pause",       sinsp_logger::SEV_EVT_INFORMATION },
			{ "rename",      sinsp_logger::SEV_EVT_INFORMATION },
			{ "resize",      sinsp_logger::SEV_EVT_INFORMATION },
			{ "restart",     sinsp_logger::SEV_EVT_WARNING     },
			{ "start",       sinsp_logger::SEV_EVT_INFORMATION },
			{ "stop",        sinsp_logger::SEV_EVT_INFORMATION },
			{ "top",         sinsp_logger::SEV_EVT_INFORMATION },
			{ "unpause",     sinsp_logger::SEV_EVT_INFORMATION },
			{ "update",      sinsp_logger::SEV_EVT_INFORMATION },

			// image
			{ "delete", sinsp_logger::SEV_EVT_INFORMATION },
			{ "import", sinsp_logger::SEV_EVT_INFORMATION },
			{ "pull",   sinsp_logger::SEV_EVT_INFORMATION },
			{ "push",   sinsp_logger::SEV_EVT_INFORMATION },
			{ "tag",    sinsp_logger::SEV_EVT_INFORMATION },
			{ "untag",  sinsp_logger::SEV_EVT_INFORMATION },

			// volume
			{ "mount",   sinsp_logger::SEV_EVT_INFORMATION },
			{ "unmount", sinsp_logger::SEV_EVT_INFORMATION },

			// network
			{ "connect",    sinsp_logger::SEV_EVT_INFORMATION },
			{ "disconnect", sinsp_logger::SEV_EVT_INFORMATION }
		},
		m_name_translation
		{
			// Container
			{ "attach",      "Attached"      },
			{ "commit",      "Committed"     },
			{ "copy",        "Copied"        },
			{ "create",      "Created"       },
			{ "destroy",     "Destroyed"     },
			{ "die",         "Died"          },
			{ "exec_create", "Exec Created"  },
			{ "exec_start",  "Exec Started"  },
			{ "export",      "Exported"      },
			{ "kill",        "Killed"        },
			{ "oom",         "Out of Memory" },
			{ "pause",       "Paused"        },
			{ "rename",      "Renamed"       },
			{ "resize",      "Resized"       },
			{ "restart",     "Restarted"     },
			{ "start",       "Started"       },
			{ "stop",        "Stopped"       },
			{ "top",         "Top"           },
			{ "unpause",     "Unpaused"      },
			{ "update",      "Updated"       },

			// Image
			{ "delete", "Deleted"  },
			{ "import", "Imported" },
			{ "pull",   "Pulled"   },
			{ "push",   "Pushed"   },
			{ "tag",    "Tagged"   },
			{ "untag",  "Untagged" },

			// Volume
			// { "create",  "Created" }, duplicate
			{ "mount",   "Mounted"   },
			{ "unmount", "Unmounted" },
			// { "destroy", "Destroyed" }, duplicate

			// Network
			// { "create",     "Created"      }, duplicate
			{ "connect",    "Connected"    },
			{ "disconnect", "Disconnected" }
			// { "destroy"     "Destroyed"    } duplicate
		}
{
	m_connection_id++;
	g_logger.log(std::string("Creating Docker object for " +
							(url.empty() ? std::string("capture replay") : url)),
				 sinsp_logger::SEV_DEBUG);
#ifdef HAS_CAPTURE
	if(url.empty())
	{
		url = std::string("file://").append(scap_get_host_root()).append(DOCKER_SOCKET_FILE);
	}
	m_event_http = std::make_shared<handler_t>(*this, "docker", url, path, http_version,
					timeout_ms, nullptr, nullptr, true, false, 524288u, false);
	m_event_http->set_json_callback(&docker::set_event_json);
	m_event_http->add_json_filter(".");
	m_collector.add(m_event_http);
	m_collector.set_steady_state(true);
	send_data_request();
#endif
}

docker::~docker()
{
}

#ifdef HAS_CAPTURE
void docker::send_event_data_request()
{
	if(m_event_http)
	{
		m_event_http->send_request();
	}
	else
	{
		throw sinsp_exception("Docker event HTTP client is null.");
	}
}

void docker::connect()
{
	if(!connect(m_event_http, &docker::set_event_json, 1))
	{
		throw sinsp_exception("Connection to Docker API failed.");
	}
	m_ever_connected = true;
}
#endif // HAS_CAPTURE

bool docker::is_alive() const
{
#ifdef HAS_CAPTURE
	if(m_event_http && !m_event_http->is_connected())
	{
		g_logger.log("Docker state connection loss.", sinsp_logger::SEV_WARNING);
		return false;
	}
#endif // HAS_CAPTURE
	return true;
}

#ifdef HAS_CAPTURE

void docker::check_collector_status()
{
	if(!m_collector.is_healthy(m_event_http))
	{
		throw sinsp_exception("Docker collector not healthy, "
							  "giving up on data collection in this cycle ...");
	}
}

void docker::send_data_request(bool collect)
{
	if(m_events.size()) { return; }
	connect();
	send_event_data_request();
	g_logger.log("Docker event request sent.", sinsp_logger::SEV_DEBUG);
	if(collect) { collect_data(); }
}

void docker::collect_data()
{
	if(m_collector.subscription_count())
	{
		if(!m_event_http->is_enabled())
		{
			m_event_http->enable();
		}
		m_collector.get_data();
		if(m_events.size())
		{
			for(auto evt : m_events)
			{
				if(evt && !evt->isNull())
				{
					handle_event(std::move(*evt));
				}
				else
				{
					g_logger.log(std::string("Docker event error: ") +
								(!evt ? "event is null." : (evt->isNull() ? "JSON is null." : "Unknown")),
								sinsp_logger::SEV_ERROR);
				}
			}
			m_events.clear();
		}
	}
}
#endif // HAS_CAPTURE

void docker::set_event_json(json_ptr_t json, const std::string&)
{
	if(m_event_filter)
	{
		m_events.emplace_back(json);
	}
}

#ifdef HAS_CAPTURE
void docker::emit_event(Json::Value& root, std::string type, std::string status, bool send_to_backend)
{
	if(send_to_backend)
	{
		++m_event_counter;
	}
	std::string::size_type delim_pos = status.find(':');
	if(delim_pos != std::string::npos)
	{
		status = status.substr(0, delim_pos);
	}
	g_logger.log("Docker EVENT: handling " + status + " of " + type, sinsp_logger::SEV_DEBUG);
	severity_map_t::const_iterator it = m_severity_map.find(status);

	severity_t severity;
	std::string event_name = status;
	std::string id = get_json_string(root, "id");
	if(id.length() > 7 && id.substr(0, 7) == "sha256:") // untag and delete have "sha256:id" format
	{
		id.clear(); // ignore that (will be displayed in event description)
	}
	if(it == m_severity_map.end())
	{
		g_logger.log("No configured severity for docker event \"" + status + "\". Assuming SEV_EVT_INFORMATION", sinsp_logger::SEV_DEBUG);
		severity = sinsp_logger::SEV_EVT_INFORMATION;
	}
	else
	{
		severity = it->second;
	}
	g_logger.log("Docker EVENT: severity for " + status + '=' + std::to_string(severity - sinsp_logger::SEV_EVT_MIN), sinsp_logger::SEV_DEBUG);
	uint64_t epoch_time_s = static_cast<uint64_t>(~0);
	Json::Value t = root["time"];
	if(!t.isNull() && t.isConvertibleTo(Json::uintValue))
	{
		epoch_time_s = t.asUInt64();
	}
	g_logger.log("Docker EVENT: name=" + event_name + ", id=" + id +
				", status=" + status + ", time=" + std::to_string(epoch_time_s),
				sinsp_logger::SEV_DEBUG);
	if(m_verbose)
	{
		std::cout << Json::FastWriter().write(root) << std::endl;
	}

	Json::Value no_value = Json::nullValue;
	const Json::Value& actor = root["Actor"];
	const Json::Value& attrib = actor.isNull() ? no_value : actor["Attributes"];
	const Json::Value& img = attrib.isNull() ? no_value : attrib["image"];
	std::string image;
	if(!img.isNull() && img.isConvertibleTo(Json::stringValue))
	{
		image = img.asString();
	}
	event_scope scope;
	if(m_machine_id.length())
	{
		scope.add("host.mac", m_machine_id);
	}
	if(is_image_event(event_name))
	{
		bool id_was_empty = false;
		if(id.empty())
		{
			id = get_json_string(root, "id");
			id_was_empty = true;
		}
		if(!id.empty())
		{
			scope.add("container.image", id);
		}
		else if(!image.empty())
		{
			scope.add("container.image", image);
		}
		else
		{
			g_logger.log("Cannot determine container image for Docker event.", sinsp_logger::SEV_WARNING);
		}
		if(id_was_empty) { id.clear(); }
	}
	else if(is_container_event(event_name))
	{
		if(id.length() >= 12)
		{
			scope.add("container.id", id.substr(0, 12));
		}
	}
	if(status.length())
	{
		status.insert(0, "Event: ", 7);
	}
	if(!actor.isNull() && actor.isObject())
	{
		if(!attrib.isNull() && attrib.isObject())
		{
			if(!image.empty())
			{
				status.append("; Image: ").append(image);
			}
			if(!id.empty() && id != image)
			{
				status.append("; ID: ").append(id);
			}
			for(const auto attribute_name : {"name", "exitCode", "signal"})
			{
				const Json::Value& name = attrib[attribute_name];
				if(!name.isNull() && name.isConvertibleTo(Json::stringValue))
				{
					status.append("; ").append(attribute_name).append(": ").append(name.asString());
				}
			}
		}
	}
	sinsp_user_event::tag_map_t tags;
	tags["source"] = "docker";
	if(event_name.length())
	{
		if(type.length())
		{
			type[0] = toupper(type[0]);
			event_name = type.append(1, ' ').append(translate_name(event_name));
		}
		else // older docker versions don't tell type
		{
			event_name[0] = toupper(event_name[0]);
			event_name.insert(0, "Docker ");
		}
	}
	std::string evt = sinsp_user_event::to_string(epoch_time_s, std::move(event_name),
						std::move(status), std::move(scope), std::move(tags));

	if(send_to_backend)
	{
		if(it != m_severity_map.end())
		{
			//
			// This is where the event is sent to the backend
			//
			g_logger.log(evt, severity);

			if(g_logger.get_severity() >= sinsp_logger::SEV_TRACE)
			{
				g_logger.log("Docker EVENT: scheduled for sending\n" + evt, sinsp_logger::SEV_TRACE);
			}
		}
		else
		{
			g_logger.log("Docker EVENT: status not supported: " + status, sinsp_logger::SEV_ERROR);
			if(g_logger.get_severity() >= sinsp_logger::SEV_DEBUG)
			{
				g_logger.log(Json::FastWriter().write(root), sinsp_logger::SEV_DEBUG);
			}
		}
	}

	//
	// This is where the event is sent to the memdumper
	//
	g_logger.log(std::move(evt), (severity_t)sinsp_logger::SEV_EVT_MDUMP);
}

void docker::handle_event(Json::Value&& root)
{
	if(m_event_filter && (m_event_counter < sinsp_user_event::max_events_per_cycle()))
	{
		std::string type = get_json_string(root, "Type");
		std::string status = get_json_string(root, "Action");
		if(status.empty())
		{
			status = get_json_string(root, "status");
		}
		g_logger.log("Docker EVENT: type=" + type + ", status=" + status + ", "
					 "queued events count=" + std::to_string(m_event_counter), sinsp_logger::SEV_DEBUG);
		bool is_allowed = m_event_filter->allows_all();
		if(!is_allowed)
		{
			if(!type.empty())
			{
				is_allowed = m_event_filter->allows_all(type);
				if(!is_allowed && !status.empty())
				{
					is_allowed = m_event_filter->has(type, status);
				}
				// status for exec_* events is different, eg.:
				//   "container:exec_create: ls -l"
				if(!is_allowed)
				{
					std::string exec_create = "exec_create";
					std::string exec_start = "exec_start";
					std::string::size_type pos = status.find(exec_create);
					if(pos != std::string::npos)
					{
						status = exec_create;
						g_logger.log("Docker EVENT: found exec_create status=" + status, sinsp_logger::SEV_TRACE);
					}
					else
					{
						pos = status.find(exec_start);
						if(pos != std::string::npos)
						{
							status = exec_start;
							g_logger.log("Docker EVENT: found exec_start status=" + status, sinsp_logger::SEV_TRACE);
						}
					}
					if(pos != std::string::npos)
					{
						is_allowed = m_event_filter->has(type, status);
						g_logger.log("Docker EVENT: status=" + status + (is_allowed ? " is " : " is not ") + "allowed",
									 sinsp_logger::SEV_TRACE);
					}
				}
			}
			else // older docker versions don't tell type, so there will be some overlap of duplicates
			{
				is_allowed = m_event_filter->has("container", status);
				if(!is_allowed && !status.empty())
				{
					is_allowed = m_event_filter->has("image", status);
				}
				if(!is_allowed && !status.empty())
				{
					is_allowed = m_event_filter->has("volume", status);
				}
				if(!is_allowed && !status.empty())
				{
					is_allowed = m_event_filter->has("volume", status);
				}
			}
		}

		if(is_allowed)
		{
			emit_event(root, type, status, true);
		}
		else
		{
			emit_event(root, type, status, false);

			if(g_logger.get_severity() >= sinsp_logger::SEV_TRACE)
			{
				g_logger.log("Docker EVENT: status not permitted by filter: " + type +':' + status, sinsp_logger::SEV_TRACE);
				g_logger.log(Json::FastWriter().write(root), sinsp_logger::SEV_TRACE);
			}
		}
		m_event_limit_exceeded = false;
	}
	else if(!m_event_limit_exceeded) // only get in here once per cycle, to send event overflow warning
	{
		sinsp_user_event::emit_event_overflow("Docker", get_machine_id());
		m_event_limit_exceeded = true;
	}
}

std::string docker::get_socket_file()
{
	string sock_file = scap_get_host_root();
	std::string::size_type len = sock_file.length();
	if(len && sock_file[len - 1] == '/')
	{
		if((len - 1) > 0)
		{
			sock_file = sock_file.substr(0, len - 1);
		}
		else
		{
			sock_file.clear();
		}
	}
	sock_file.append(DOCKER_SOCKET_FILE);
	return sock_file;
}
#endif // HAS_CAPTURE

#endif // __linux__
