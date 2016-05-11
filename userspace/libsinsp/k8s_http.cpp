//
// k8s_http.cpp
//

#ifdef HAS_CAPTURE

#include "k8s_http.h"
#include "curl/curl.h"
#include "curl/easy.h"
#include "curl/curlbuild.h"
#define BUFFERSIZE 512 // b64 needs this macro
#include "b64/encode.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "k8s.h"
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <unistd.h>

k8s_http::k8s_http(k8s& k8s,
	const std::string& component,
	const std::string& host_and_port,
	const std::string& protocol,
	const std::string& credentials,
	const std::string& api,
	ssl_ptr_t ssl,
	bt_ptr_t bt,
	bool curl_debug):
		m_curl(curl_easy_init()),
		m_k8s(k8s),
		m_protocol(protocol),
		m_host_and_port(host_and_port),
		m_api(api),
		m_component(component),
		m_credentials(credentials),
		m_ssl(ssl),
		m_bt(bt),
		m_watch_socket(0),
		m_data_ready(false)
{
	if(!m_curl)
	{
		throw sinsp_exception("CURL initialization failed.");
	}

	curl_version_info_data* data = curl_version_info(CURLVERSION_NOW);
	if((protocol == "https"))
	{
		if(!(data->features | CURL_VERSION_SSL))
		{
			cleanup();
			throw sinsp_exception("Curl HTTPS NOT supported");
		}
		if(!m_ssl)
		{
			throw sinsp_exception("K8S: HTTPS connection detected but SSL object is null.");
		}
		sinsp_curl::init_ssl(m_curl, m_ssl);
	}
	else if((protocol != "http"))
	{
		cleanup();
		throw sinsp_exception("Protocol not supported:" + protocol);
	}

	if(m_bt)
	{
		sinsp_curl::init_bt(m_curl, m_bt);
	}

	if(curl_debug)
	{
		sinsp_curl::enable_debug(m_curl, true);
	}

	std::ostringstream url;
	url << m_protocol << "://";
	if(!m_credentials.empty())
	{
		url << m_credentials << '@';
	}
	url << m_host_and_port;
	url << m_api << '/' << m_component << std::flush;
	m_url = url.str();
}

k8s_http::~k8s_http()
{
	cleanup();
}

bool k8s_http::init()
{
	if(!m_curl)
	{
		cleanup();
		m_curl = curl_easy_init();
	}
	return m_curl != 0;
}

void k8s_http::cleanup()
{
	if(m_curl)
	{
		curl_easy_cleanup(m_curl);
		m_curl = 0;
	}
}

size_t k8s_http::write_data(void *ptr, size_t size, size_t nmemb, void *cb)
{
	std::string data(reinterpret_cast<const char*>(ptr), static_cast<size_t>(size * nmemb));
	*reinterpret_cast<std::ostream*>(cb) << data << std::flush;
	return size * nmemb;
}

bool k8s_http::get_all_data(std::ostream& os, long timeout_ms)
{
	CURLcode res = CURLE_OK;

	g_logger.log(std::string("Retrieving all K8S data from ") + uri(m_url).to_string(false), sinsp_logger::SEV_DEBUG);
	check_error(curl_easy_setopt(m_curl, CURLOPT_URL, m_url.c_str()));
	check_error(curl_easy_setopt(m_curl, CURLOPT_FOLLOWLOCATION, 1L));

	check_error(curl_easy_setopt(m_curl, CURLOPT_NOSIGNAL, 1)); //Prevent "longjmp causes uninitialized stack frame" bug
	check_error(curl_easy_setopt(m_curl, CURLOPT_ACCEPT_ENCODING, "deflate"));
	check_error(curl_easy_setopt(m_curl, CURLOPT_TIMEOUT_MS, timeout_ms));
	check_error(curl_easy_setopt(m_curl, CURLOPT_WRITEFUNCTION, &k8s_http::write_data));
	check_error(curl_easy_setopt(m_curl, CURLOPT_WRITEDATA, &os));

	res = curl_easy_perform(m_curl);
	if(res != CURLE_OK)
	{
		os << curl_easy_strerror(res) << std::flush;
	}
	else
	{
		// HTTP errors are not returned by curl API
		// error will be in the response stream
		long http_code = 0;
		curl_easy_getinfo(m_curl, CURLINFO_RESPONSE_CODE, &http_code);
		if(http_code >= 400)
		{
			return false;
		}
	}

	return res == CURLE_OK;
}

int k8s_http::wait(curl_socket_t sockfd, int for_recv, long timeout_ms)
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

int k8s_http::get_watch_socket(long timeout_ms)
{
	if(!m_watch_socket)
	{
		long sockextr;
		size_t iolen;
		std::string url = m_url;
		url.insert(m_url.find(m_api) + m_api.size(), "/watch");

		check_error(curl_easy_setopt(m_curl, CURLOPT_URL, url.c_str()));
		check_error(curl_easy_setopt(m_curl, CURLOPT_CONNECT_ONLY, 1L));

		check_error(curl_easy_perform(m_curl));

		check_error(curl_easy_getinfo(m_curl, CURLINFO_LASTSOCKET, &sockextr));
		m_watch_socket = sockextr;

		if(!wait(m_watch_socket, 0, timeout_ms))
		{
			cleanup();
			throw sinsp_exception("Error: timeout.");
		}

		std::ostringstream request;
		request << "GET /api/v1/watch/" << m_component << " HTTP/1.0\r\nHost: " << m_host_and_port << "\r\nConnection: Keep-Alive\r\n";
		if(!m_credentials.empty())
		{
			std::string::size_type pos = m_credentials.find(':');
			if(pos == std::string::npos)
			{
				throw sinsp_exception("Invalid credentials (missing ':' separator)");
			}
			std::string username = uri::decode(m_credentials.substr(0, pos));
			std::string password;
			if(m_credentials.length() > pos)
			{
				password = uri::decode(m_credentials.substr(pos + 1));
			}
			std::istringstream is(username.append(1, ':').append(password));
			std::ostringstream os;
			base64::encoder().encode(is, os);
			request << "Authorization: Basic " << os.str() << "\r\n";
		}
		if(m_bt && !m_bt->get_token().empty())
		{
			request << "Authorization: Bearer " << m_bt->get_token() << "\r\n";
		}
		request << "\r\n";
		check_error(curl_easy_send(m_curl, request.str().c_str(), request.str().size(), &iolen));
		ASSERT (request.str().size() == iolen);
		if(!wait(m_watch_socket, 1, timeout_ms))
		{
			cleanup();
			throw sinsp_exception("Error: timeout.");
		}

		g_logger.log(std::string("Collecting data from ") + uri(url).to_string(false), sinsp_logger::SEV_DEBUG);
	}

	return m_watch_socket;
}

bool k8s_http::on_data()
{
	size_t iolen = 0;
	char buf[1024] = { 0 };
	CURLcode ret;

	do
	{
		iolen = 0;
		try
		{
			check_error(ret = curl_easy_recv(m_curl, buf, 1024, &iolen));
		}
		catch(sinsp_exception& ex)
		{
			g_logger.log(std::string("Data receive error: ").append(ex.what()), sinsp_logger::SEV_ERROR);
			return false;
		}
		if(iolen > 0)
		{
			if(m_data_ready)
			{
				m_k8s.on_watch_data(k8s_event_data(k8s_component::get_type(m_component), buf, iolen));
			}
			else // wait for a line with "\r\n" only
			{
				std::string data(buf, iolen);
				std::string end = "\r\n\r\n";
				std::string::size_type pos = data.find(end);
				if(pos != std::string::npos)
				{
					pos += end.size();
					if(iolen == pos) // right on the edge of data
					{
						m_data_ready = true;
					}
					else
					{
						char* pbuf = &buf[pos];
						m_data_ready = true;
						m_k8s.on_watch_data(k8s_event_data(k8s_component::get_type(m_component), pbuf, iolen - pos));
					}
				}
			}
		}
		else if(ret != CURLE_AGAIN)
		{
			g_logger.log("Connection closed", sinsp_logger::SEV_ERROR);
			m_data_ready = false;
			return false;
		}
	} while(iolen && ret != CURLE_AGAIN);

	return true;
}


void k8s_http::on_error(const std::string& err, bool disconnect)
{
	g_logger.log("Socket error:" + err, sinsp_logger::SEV_ERROR);
	if(disconnect)
	{
		cleanup();
	}
}

void k8s_http::check_error(CURLcode res)
{
	if(CURLE_OK != res && CURLE_AGAIN != res)
	{
		std::ostringstream os;
		os << "Error: " << curl_easy_strerror(res);
		throw sinsp_exception(os.str());
	}
}

#endif // HAS_CAPTURE
