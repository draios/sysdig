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
#include <string.h>

mesos_http::mesos_http(mesos& m, const uri& url):
	m_sync_curl(curl_easy_init()),
	m_select_curl(curl_easy_init()),
	m_mesos(m),
	m_url(url),
	m_connected(true),
	m_watch_socket(-1),
	m_timeout_ms(5000L),
	m_callback_func(0),
	m_curl_version(curl_version_info(CURLVERSION_NOW)),
	m_request(make_request(url, m_curl_version))
{
	if(!m_sync_curl || !m_select_curl)
	{
		throw sinsp_exception("CURL initialization failed.");
	}

	ASSERT(m_curl_version);
	if((m_url.get_scheme() == "https") && (m_curl_version && !(m_curl_version->features | CURL_VERSION_SSL)))
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
	cleanup(m_sync_curl);
	cleanup(m_select_curl);
}

void mesos_http::cleanup(CURL* curl)
{
	if(curl)
	{
		curl_easy_cleanup(curl);
		curl = 0;
		m_connected = false;
	}
}

std::string mesos_http::make_request(uri url, curl_version_info_data* curl_version)
{
	std::ostringstream request;
	std::string host_and_port = url.get_host();
	int port = url.get_port();
	if(port)
	{
		host_and_port.append(1, ':').append(std::to_string(port));
	}
	request << "GET " << url.get_path();
	std::string query = url.get_query();
	if(!query.empty())
	{
		request << '?' << query;
	}
	request << " HTTP/1.1\r\nConnection: Keep-Alive\r\nUser-Agent: sysdig";
	if(curl_version && curl_version->version)
	{
		request << " (curl " << curl_version->version << ')';
	}
	request << "\r\nHost: " << host_and_port << "\r\nAccept: */*\r\n";
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
	curl_easy_setopt(m_sync_curl, CURLOPT_URL, url.c_str());
	curl_easy_setopt(m_sync_curl, CURLOPT_FOLLOWLOCATION, 1L);

	if(m_url.get_scheme() == "https")
	{
		check_error(curl_easy_setopt(m_sync_curl, CURLOPT_SSL_VERIFYPEER , 0));
	}

	curl_easy_setopt(m_sync_curl, CURLOPT_NOSIGNAL, 1); //Prevent "longjmp causes uninitialized stack frame" bug
	curl_easy_setopt(m_sync_curl, CURLOPT_ACCEPT_ENCODING, "deflate");
	curl_easy_setopt(m_sync_curl, CURLOPT_WRITEFUNCTION, &mesos_http::write_data);

	curl_easy_setopt(m_sync_curl, CURLOPT_WRITEDATA, &os);
	return curl_easy_perform(m_sync_curl);
}

bool mesos_http::get_all_data(callback_func_t parse)
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
		(m_mesos.*parse)(os.str(), m_framework_id);
		m_connected = true;
	}

	return res == CURLE_OK;
}

int mesos_http::wait(int for_recv)
{
	struct timeval tv;
	fd_set infd, outfd, errfd;
	int res;

	tv.tv_sec = m_timeout_ms / 1000;
	tv.tv_usec = (m_timeout_ms % 1000) * 1000;

	FD_ZERO(&infd);
	FD_ZERO(&outfd);
	FD_ZERO(&errfd);

	FD_SET(m_watch_socket, &errfd);

	if(for_recv)
	{
		FD_SET(m_watch_socket, &infd);
	}
	else
	{
		FD_SET(m_watch_socket, &outfd);
	}

	res = select(m_watch_socket + 1, &infd, &outfd, &errfd, &tv);
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

		check_error(curl_easy_setopt(m_select_curl, CURLOPT_URL, url.c_str()));
		check_error(curl_easy_setopt(m_select_curl, CURLOPT_CONNECT_ONLY, 1L));
		// enable TCP keep-alive for this transfer
		check_error(curl_easy_setopt(m_select_curl, CURLOPT_TCP_KEEPALIVE, 1L));
		// keep-alive idle time to 120 seconds
		check_error(curl_easy_setopt(m_select_curl, CURLOPT_TCP_KEEPIDLE, 120L));
		// interval time between keep-alive probes: 10 seconds
		check_error(curl_easy_setopt(m_select_curl, CURLOPT_TCP_KEEPINTVL, 10L));

		check_error(curl_easy_perform(m_select_curl));

		check_error(curl_easy_getinfo(m_select_curl, CURLINFO_LASTSOCKET, &sockextr));
		m_watch_socket = sockextr;

		if(!wait(0))
		{
			cleanup(m_select_curl);
			throw sinsp_exception("Error obtaining socket: timeout.");
		}

		g_logger.log(std::string("Connected: collecting data from ") + url, sinsp_logger::SEV_DEBUG);
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
		throw sinsp_exception("Cannot send request (empty).");
	}

	if(m_watch_socket < 0)
	{
		m_connected = false;
		throw sinsp_exception("Cannot create watch socket (invalid socket).");
	}

	size_t iolen = send(m_watch_socket, m_request.c_str(), m_request.size(), 0);
	if(iolen <= 0)
	{
		cleanup(m_select_curl);
		throw sinsp_exception("Socket connection error.");
	}
	else if(!wait(1))
	{
		cleanup();
		throw sinsp_exception("Error: timeout.");
	}
	ASSERT (m_request.size() == iolen);
	g_logger.log(m_request, sinsp_logger::SEV_DEBUG);
}

void mesos_http::add_data_chunk(std::istringstream&& chunk_str)
{
	std::string chunk;
	while(std::getline(chunk_str, chunk))
	{
		std::string::size_type sz = chunk.size();
		if(sz)
		{
			chunk.erase(std::remove_if(chunk.begin(), chunk.end(), [](char c) { return c == '\r' || c == '\n'; }), chunk.end());
			if(chunk == "HTTP/1.1 200 OK") // new request, start fresh
			{
				m_data_buf.clear();
				continue;
			}

			sz = chunk.size();
			if(sz)
			{
				bool json_begin = (chunk[0] == '{');
				if(json_begin)
				{
					m_data_buf.append(chunk);
					sz = m_data_buf.size();
					bool json_end = m_data_buf[sz - 1] == '}';
					if(json_end && try_parse(m_data_buf))
					{
						(m_mesos.*m_callback_func)(std::move(m_data_buf), m_framework_id);
						m_data_buf.clear();
					}
				}
			}
		}
	}
}

void mesos_http::extract_data(const std::string& data)
{
	if(data.size())
	{
		const std::string delim = "\r\n\r\n";
		std::string::size_type begin_pos = 0;
		std::string::size_type end_pos = data.find(delim);
		if(end_pos == std::string::npos)
		{
			add_data_chunk(std::istringstream(data));
			return;
		}

		while(true)
		{
			add_data_chunk(std::istringstream(data.substr(begin_pos, end_pos - begin_pos)));
			begin_pos = end_pos + delim.size();
			end_pos = data.find(delim, begin_pos);
			if(end_pos == std::string::npos)
			{
				add_data_chunk(std::istringstream(data.substr(begin_pos)));
				break;
			}
		}
	}
}

bool mesos_http::on_data()
{
	if(!m_callback_func)
	{
		throw sinsp_exception("Cannot parse data (parse function null).");
	}

	size_t iolen = 0;
	std::vector<char> buf;
	std::string data;

	try
	{
		do
		{
			size_t iolen = 0;
			int count = 0;
			int ioret = 0;
			ioret = ioctl(m_watch_socket, FIONREAD, &count);
			if(ioret >= 0 && count)
			{
				if(count > static_cast<int>(buf.size()))
				{
					buf.resize(count);
				}
				iolen = recv(m_watch_socket, &buf[0], count, 0);
			}
			else
			{
				if(ioret < 0)
				{
					std::string err = strerror(errno);
					g_logger.log("mesos_http::on_data() error : " + err, sinsp_logger::SEV_ERROR);
					return false;
				}
				break;
			}
			if(iolen > 0)
			{
				data.append(&buf[0], iolen <= buf.size() ? iolen : buf.size());
			}
			else if(iolen == 0)
			{
				g_logger.log("Mesos or Marathon API connection closed", sinsp_logger::SEV_ERROR);
				m_connected = false;
				return false;
			}
		} while(iolen && errno != CURLE_AGAIN);
		if(data.size())
		{
			extract_data(data);
		}
	}
	catch(sinsp_exception& ex)
	{
		g_logger.log(std::string("Data receive error: ").append(ex.what()), sinsp_logger::SEV_ERROR);
		return false;
	}
	return true;
}

void mesos_http::on_error(const std::string& /*err*/, bool /*disconnect*/)
{
	m_connected = false;
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
