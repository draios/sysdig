//
// marathon_http.cpp
//

#ifdef HAS_CAPTURE

#include "marathon_http.h"
#include "curl/curl.h"
#include "curl/easy.h"
#include "curl/curlbuild.h"
#define BUFFERSIZE 512 // b64 needs this macro
#include "b64/encode.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "mesos.h"
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <unistd.h>

marathon_http::marathon_http(mesos& m, const uri& url): mesos_http(m, url)
{
	g_logger.log("Creating Marathon HTTP object for [" + url.to_string() + "] ...", sinsp_logger::SEV_DEBUG);
	if(refresh_data())
	{
		g_logger.log("Created Marathon HTTP connection (" + url.to_string() + ") for framework [" + get_framework_name() + "] (" + get_framework_id() + "), version: " + get_framework_version(), sinsp_logger::SEV_INFO);
	}
	else
	{
		throw sinsp_exception("Could not obtain Mesos Marathon framework information.");
	}

	g_logger.log("Marathon request [" + get_request() + ']', sinsp_logger::SEV_DEBUG);
}

marathon_http::~marathon_http()
{
}

bool marathon_http::refresh_data()
{
	std::ostringstream os;
	CURLcode res = get_data(make_uri("/v2/info"), os);

	if(res != CURLE_OK)
	{
		g_logger.log(curl_easy_strerror(res), sinsp_logger::SEV_ERROR);
		return false;
	}

	try
	{
		Json::Value root;
		Json::Reader reader;
		if(reader.parse(os.str(), root, false))
		{
			set_framework_id(get_json_string(root, "frameworkId"));
			set_framework_name(get_json_string(root, "name"));
			set_framework_version(get_json_string(root, "version"));
			g_logger.log("Found Marathon framework: " + get_framework_name() + " (" + get_framework_id() + "), version: " + get_framework_version(), sinsp_logger::SEV_DEBUG);
		}
		else
		{
			g_logger.log("Error parsing framework info.\nJSON:\n---\n" + os.str() + "\n---", sinsp_logger::SEV_ERROR);
			return false;
		}
	}
	catch(std::exception& ex)
	{
		g_logger.log(std::string("Error parsing framework info:") + ex.what(), sinsp_logger::SEV_ERROR);
		return false;
	}
	
	return true;
}
/*TODO: see comment in mesos.cpp constructor
bool marathon_http::on_data()
{
	size_t iolen = 0;
	char buf[1024] = { 0 };
	CURLcode ret;

	do
	{
		iolen = 0;
		try
		{
			check_error(ret = curl_easy_recv(get_curl(), buf, 1024, &iolen));
		}
		catch(sinsp_exception& ex)
		{
			g_logger.log(std::string("Data receive error: ").append(ex.what()), sinsp_logger::SEV_ERROR);
			return false;
		}
		if(iolen > 0)
		{
			m_data.append(buf, iolen);
		}
		else if(ret != CURLE_AGAIN)
		{
			g_logger.log("Connection closed", sinsp_logger::SEV_ERROR);
			return false;
		}
	} while(iolen && ret != CURLE_AGAIN);

	const std::string end = "\r\n\r\n";
	std::string::size_type pos = m_data.find(end);
	while(!m_data.empty() && pos != std::string::npos)
	{
		std::string msg = m_data.substr(0, pos);
		trim(msg);
		if(msg.size() && msg.find("event:") != std::string::npos)
		{
			try
			{
				if(!mesos_event_data::is_ignored(mesos_event_data::get_event_type(msg)))
				{
					get_mesos().on_watch_data(get_framework_id(), mesos_event_data(msg));
				}
			}
			catch(std::exception& ex)
			{
				g_logger.log(ex.what(), sinsp_logger::SEV_ERROR);
				return false;
			}
		}
		m_data = m_data.substr(pos + end.size());
		pos = m_data.find(end);
	}

	return true;
}
*/
std::string marathon_http::get_groups(const std::string& group_id)
{
	std::ostringstream os;
	CURLcode res = get_data(make_uri("/v2/groups" + group_id), os);

	if(res != CURLE_OK)
	{
		g_logger.log(curl_easy_strerror(res), sinsp_logger::SEV_ERROR);
		return "";
	}

	return os.str();
}

/*
void marathon_http::on_error(const std::string& err, bool disconnect)
{
	g_logger.log("Socket error:" + err, sinsp_logger::SEV_ERROR);
	if(disconnect)
	{
		cleanup();
	}
}
*/
#endif // HAS_CAPTURE
