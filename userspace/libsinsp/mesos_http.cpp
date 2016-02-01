//
// mesos_http.cpp
//

#ifdef HAS_CAPTURE

#include "mesos_http.h"
#include "curl/curl.h"
#include "curl/easy.h"
#include "curl/curlbuild.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "mesos.h"
#define BUFFERSIZE 512 // b64 needs this macro
#include "b64/encode.h"
#include <sstream>
#include <stdexcept>
#include <unistd.h>
#include <sys/ioctl.h>

mesos_http::mesos_http(mesos& m, const uri& url):
	m_curl(curl_easy_init()),
	m_mesos(m),
	m_url(url),
	m_connected(true),
	m_watch_socket(-1),
	m_timeout_ms(5000L),
	m_request(make_request(url)),
	m_parse_func(0)
{
	if(!m_curl)
	{
		throw sinsp_exception("CURL initialization failed.");
	}

	curl_version_info_data* data = curl_version_info(CURLVERSION_NOW);
	if((m_url.get_scheme() == "https") && !(data->features | CURL_VERSION_SSL))
	{
		cleanup();
		throw sinsp_exception("HTTPS NOT supported");
	}
}

mesos_http::~mesos_http()
{
	cleanup();
}

void mesos_http::cleanup()
{
	if(m_curl)
	{
		curl_easy_cleanup(m_curl);
		m_curl = 0;
		m_connected = false;
	}
}

std::string mesos_http::make_request(uri url)
{
	std::ostringstream request;
	std::string host_and_port = url.get_host();
	int port = url.get_port();
	if(port)
	{
		host_and_port.append(1, ':').append(std::to_string(port));
	}
	request << "GET " << url.get_path() << " HTTP/1.1\r\nHost: " << host_and_port << "\r\n";
	std::string creds = url.get_credentials();
	if(!creds.empty())
	{
		std::istringstream is(creds);
		std::ostringstream os;
		base64::encoder().encode(is, os);
		request << "Authorization: Basic " << os.str() << "\r\n";
	}
	request << "\r\n";

	return request.str();
}

size_t mesos_http::write_data(void *ptr, size_t size, size_t nmemb, void *cb)
{
	std::string data(reinterpret_cast<const char*>(ptr), static_cast<size_t>(size * nmemb));
	*reinterpret_cast<std::ostream*>(cb) << data << std::flush;
	return size * nmemb;
}

CURLcode mesos_http::get_data(const std::string& url, std::ostream& os)
{
	g_logger.log(std::string("Retrieving data from ") + url, sinsp_logger::SEV_DEBUG);
	curl_easy_setopt(m_curl, CURLOPT_URL, url.c_str());
	curl_easy_setopt(m_curl, CURLOPT_FOLLOWLOCATION, 1L);

	if(m_url.get_scheme() == "https")
	{
		check_error(curl_easy_setopt(m_curl, CURLOPT_SSL_VERIFYPEER , 0));
	}

	curl_easy_setopt(m_curl, CURLOPT_NOSIGNAL, 1); //Prevent "longjmp causes uninitialized stack frame" bug
	curl_easy_setopt(m_curl, CURLOPT_ACCEPT_ENCODING, "deflate");
	curl_easy_setopt(m_curl, CURLOPT_WRITEFUNCTION, &mesos_http::write_data);

	curl_easy_setopt(m_curl, CURLOPT_WRITEDATA, &os);
	return curl_easy_perform(m_curl);
}

bool mesos_http::get_all_data(parse_func_t parse)
{
	std::ostringstream os;
	CURLcode res = get_data(m_url.to_string(), os);

	if(res != CURLE_OK)
	{
		g_logger.log(curl_easy_strerror(res), sinsp_logger::SEV_ERROR);
		m_connected = false;
	}
	else
	{
		(m_mesos.*parse)(os.str());
		m_connected = true;
	}

	return res == CURLE_OK;
}

int mesos_http::wait(int for_recv)
{
	curl_socket_t sockfd = m_watch_socket;

	struct timeval tv;
	fd_set infd, outfd, errfd;
	int res;

	tv.tv_sec = m_timeout_ms / 1000;
	tv.tv_usec = (m_timeout_ms % 1000) * 1000;

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

int mesos_http::get_socket(long timeout_ms)
{
	if(m_request.empty())
	{
		throw sinsp_exception("Cannot create watch socket (request empty).");
	}

	if(timeout_ms != -1)
	{
		m_timeout_ms = timeout_ms;
	}

	if(m_watch_socket < 0 || !m_connected)
	{
		long sockextr;
		std::string url = get_url().to_string();

		check_error(curl_easy_setopt(m_curl, CURLOPT_URL, url.c_str()));
		check_error(curl_easy_setopt(m_curl, CURLOPT_CONNECT_ONLY, 1L));

		check_error(curl_easy_perform(m_curl));

		check_error(curl_easy_getinfo(m_curl, CURLINFO_LASTSOCKET, &sockextr));
		m_watch_socket = sockextr;

		if(!wait(0))
		{
			cleanup();
			throw sinsp_exception("Error obtaining socket: timeout.");
		}

		send_request();
		g_logger.log(std::string("Collecting data from ") + url, sinsp_logger::SEV_DEBUG);
	}

	if(m_watch_socket <= 0)
	{
		throw sinsp_exception("Error obtaining socket: " + std::to_string(m_watch_socket));
	}

	m_connected = true;
	return m_watch_socket;
}

void mesos_http::send_request()
{
	if(m_request.empty())
	{
		throw sinsp_exception("Cannot create watch socket (request empty).");
	}

	if(m_watch_socket < 0)
	{
		m_connected = false;
		throw sinsp_exception("Cannot create watch socket (invalid socket).");
	}

	size_t iolen;
	check_error(curl_easy_send(m_curl, m_request.c_str(), m_request.size(), &iolen));
	ASSERT (m_request.size() == iolen);
	if(!wait(1))
	{
		cleanup();
		throw sinsp_exception("Error: timeout.");
	}
}

bool mesos_http::on_data()
{
	if(!m_parse_func)
	{
		throw sinsp_exception("Cannot parse data (parse function null).");
	}

	size_t iolen = 0;
	std::vector<char> buf;
	CURLcode ret;

	do
	{
		iolen = 0;
		try
		{
			int count = 0;
			ioctl(m_watch_socket, FIONREAD, &count);
			if(count)
			{
				if(count > static_cast<int>(buf.size())) { buf.resize(count); }
				check_error(ret = curl_easy_recv(m_curl, &buf[0], buf.size(), &iolen));
			}
			else { break; }
		}
		catch(sinsp_exception& ex)
		{
			g_logger.log(std::string("Data receive error: ").append(ex.what()), sinsp_logger::SEV_ERROR);
			return false;
		}
		if(iolen > 0)
		{
			m_data.append(&buf[0], iolen <= buf.size() ? iolen : buf.size());
		}
		else if(ret != CURLE_AGAIN)
		{
			g_logger.log("Connection closed", sinsp_logger::SEV_ERROR);
			return false;
		}
	} while(iolen && ret != CURLE_AGAIN);
 
	if(m_data.size())
	{
		const std::string brk = "\r\n\r\n";
		std::string::size_type pos = m_data.find(brk);
		if(pos != std::string::npos)
		{
			m_data = m_data.substr(pos + brk.size());
		}
		//g_logger.log("Data:" + m_data, sinsp_logger::SEV_DEBUG);
		if(try_parse(m_data))
		{
			(m_mesos.*m_parse_func)(m_data);
			m_data.clear();
			send_request();
		}
	}
	else
	{
		return false;
	}

	return true;
}

void mesos_http::on_error(const std::string& /*err*/, bool /*disconnect*/)
{
	m_data.clear();
}

void mesos_http::check_error(CURLcode res)
{
	if(CURLE_OK != res && CURLE_AGAIN != res)
	{
		m_connected = false;
		std::ostringstream os;
		os << "Error: " << curl_easy_strerror(res);
		throw sinsp_exception(os.str());
	}
}

std::string mesos_http::make_uri(const std::string& path)
{
	uri url = get_url();
	std::string target_uri = url.get_scheme();
	target_uri.append("://");
	std::string user = url.get_user();
	if(!user.empty())
	{
		target_uri.append(user).append(1, ':').append(url.get_password()).append(1, '@');
	}
	target_uri.append(url.get_host());
	int port = url.get_port();
	if(port)
	{
		target_uri.append(1, ':').append(std::to_string(port));
	}
	target_uri.append(path);
	return target_uri;
}

Json::Value mesos_http::get_task_labels(const std::string& task_id)
{
	std::ostringstream os;
	CURLcode res = get_data(make_uri("/master/tasks"), os);

	Json::Value labels;
	if(res != CURLE_OK)
	{
		g_logger.log(curl_easy_strerror(res), sinsp_logger::SEV_ERROR);
		return labels;
	}

	try
	{
		Json::Value root;
		Json::Reader reader;
		if(reader.parse(os.str(), root, false))
		{
			Json::Value tasks = root["tasks"];
			if(!tasks.isNull())
			{
				for(const auto& task : tasks)
				{
					Json::Value id = task["id"];
					if(!id.isNull() && id.isString() && id.asString() == task_id)
					{
						Json::Value statuses = task["statuses"];
						if(!statuses.isNull())
						{
							double tstamp = 0.0;
							for(const auto& status : statuses)
							{
								// only task with most recent status
								// "TASK_RUNNING" considered
								Json::Value ts = status["timestamp"];
								if(!ts.isNull() && ts.isNumeric() && ts.asDouble() > tstamp)
								{
									Json::Value st = status["state"];
									if(!st.isNull() && st.isString())
									{
										if(st.asString() == "TASK_RUNNING")
										{
											labels = task["labels"];
											tstamp = ts.asDouble();
										}
										else
										{
											labels.clear();
										}
									}
								}
							}
							if(!labels.empty()) // currently running task found
							{
								return labels;
							}
						}
					}
				}
			}
		}
		else
		{
			g_logger.log("Error parsing tasks.\nJSON:\n---\n" + os.str() + "\n---", sinsp_logger::SEV_ERROR);
		}
	}
	catch(std::exception& ex)
	{
		g_logger.log(std::string("Error parsing tasks:") + ex.what(), sinsp_logger::SEV_ERROR);
	}

	return labels;
}

#endif // HAS_CAPTURE
