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

marathon_http::marathon_http(mesos& m, const uri& url, bool framework_info): mesos_http(m, url),
	m_watch_socket(-1)
{
	if(framework_info)
	{
		g_logger.log("Creating Marathon HTTP object for [" + url.to_string() + "] ...", sinsp_logger::SEV_DEBUG);
		if(refresh_data())
		{
			g_logger.log("Created Marathon HTTP object: " + m_name + " (" + m_id + "), version: " + m_version, sinsp_logger::SEV_DEBUG);
		}
		else
		{
			throw sinsp_exception("Could not obtain Mesos Marathon framework information.");
		}
	}
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
			m_id = get_json_string(root, "frameworkId");
			m_name = get_json_string(root, "name");
			m_version = get_json_string(root, "version");
			g_logger.log("Found Marathon framework: " + m_name + " (" + m_id + "), version: " + m_version, sinsp_logger::SEV_DEBUG);
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

int marathon_http::wait(curl_socket_t sockfd, int for_recv, long timeout_ms)
{
	struct timeval tv;
	fd_set infd, outfd, errfd;
	int res;

	tv.tv_sec = timeout_ms / 1000;
	tv.tv_usec = (timeout_ms % 1000) * 1000;

	FD_ZERO(&infd);
	FD_ZERO(&outfd);
	FD_ZERO(&errfd);

	FD_SET(sockfd, &errfd);

	if(for_recv)
	{
		FD_SET(sockfd, &infd);
	}
	else
	{
		FD_SET(sockfd, &outfd);
	}

	res = select(sockfd + 1, &infd, &outfd, &errfd, &tv);
	return res;
}

int marathon_http::get_watch_socket(long timeout_ms)
{
	if(m_watch_socket < 0)
	{
		long sockextr;
		size_t iolen;
		std::string url = get_url().to_string();

		check_error(curl_easy_setopt(get_curl(), CURLOPT_URL, url.c_str()));
		check_error(curl_easy_setopt(get_curl(), CURLOPT_CONNECT_ONLY, 1L));

		check_error(curl_easy_perform(get_curl()));

		check_error(curl_easy_getinfo(get_curl(), CURLINFO_LASTSOCKET, &sockextr));
		m_watch_socket = sockextr;

		if(!wait(m_watch_socket, 0, timeout_ms))
		{
			cleanup();
			throw sinsp_exception("Error: timeout.");
		}

		std::ostringstream request;
		std::string host_and_port = get_url().get_host();
		int port = get_url().get_port();
		if(port)
		{
			host_and_port.append(1, ':').append(std::to_string(port));
		}
		request << "GET " << get_url().get_path() << " HTTP/1.1\r\nHost: " << host_and_port << "\r\nAccept: text/event-stream\r\n";
		if(!get_credentials().empty())
		{
			std::istringstream is(get_credentials());
			std::ostringstream os;
			base64::encoder().encode(is, os);
			request << "Authorization: Basic " << os.str() << "\r\n";
		}
		request << "\r\n";
		check_error(curl_easy_send(get_curl(), request.str().c_str(), request.str().size(), &iolen));
		ASSERT (request.str().size() == iolen);
		if(!wait(m_watch_socket, 1, timeout_ms))
		{
			cleanup();
			throw sinsp_exception("Error: timeout.");
		}

		g_logger.log(std::string("Collecting data from ") + url, sinsp_logger::SEV_DEBUG);
	}

	return m_watch_socket;
}

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
					get_mesos().on_watch_data(m_id, mesos_event_data(msg));
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


void marathon_http::on_error(const std::string& err, bool disconnect)
{
	g_logger.log("Socket error:" + err, sinsp_logger::SEV_ERROR);
	if(disconnect)
	{
		cleanup();
	}
}

#endif // HAS_CAPTURE
