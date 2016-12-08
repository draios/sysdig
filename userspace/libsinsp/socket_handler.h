//
// socket_handler.h
//

#pragma once

#ifdef HAS_CAPTURE

#include "http_parser.h"
#include "uri.h"
#include "json/json.h"
#define BUFFERSIZE 512 // b64 needs this macro
#include "b64/encode.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "sinsp_auth.h"
#include "json_query.h"
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <iostream>
#include <string>
#include <map>
#include <memory>
#include <cstring>
#include <climits>

#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK 0
#endif

template <typename T>
class socket_data_handler
{
public:
	typedef std::shared_ptr<socket_data_handler> ptr_t;
	typedef std::shared_ptr<Json::Value>         json_ptr_t;
	typedef sinsp_ssl::ptr_t                     ssl_ptr_t;
	typedef sinsp_bearer_token::ptr_t            bt_ptr_t;
	typedef void (T::*json_callback_func_t)(json_ptr_t, const std::string&);

	static const std::string HTTP_VERSION_10;
	static const std::string HTTP_VERSION_11;
	static const int CONNECTION_CLOSED = ~0;

	socket_data_handler(T& obj,
		const std::string& id,
		const std::string& url,
		const std::string& path = "",
		const std::string& http_version = HTTP_VERSION_11,
		int timeout_ms = 1000L,
		ssl_ptr_t ssl = 0,
		bt_ptr_t bt = 0,
		bool keep_alive = true,
		bool blocking = false): m_obj(obj),
			m_id(id),
			m_url(url),
			m_keep_alive(keep_alive ? std::string("Connection: keep-alive\r\n") : std::string()),
			m_path(path.empty() ? m_url.get_path() : path),
			m_blocking(blocking),
			m_ssl(ssl),
			m_bt(bt),
			m_timeout_ms(timeout_ms),
			m_request(make_request(url, http_version)),
			m_http_version(http_version)
	{
		g_logger.log(std::string("Creating Socket handler object for (" + id + ") "
					 "[" + uri(url).to_string(false) + ']'), sinsp_logger::SEV_DEBUG);
		m_buf.resize(1024);
		init_http_parser();
	}

	virtual ~socket_data_handler()
	{
		cleanup();
	}

	virtual int get_socket(long timeout_ms = -1)
	{
		if(timeout_ms != -1)
		{
			m_timeout_ms = timeout_ms;
		}

		if(m_socket < 0 || !m_connected)
		{
			connect_socket();
		}

		return m_socket;
	}

	virtual bool is_connected() const
	{
		return m_connected;
	}

	bool is_connecting()
	{
		if(m_address.empty())
		{
			try_resolve();
		}
		if(!m_connected && m_sa && m_sa_len)
		{
			try_connect();
		}
		return m_connecting;
	}

	void close_on_chunked_end(bool close = true)
	{
		m_close_on_chunked_end = close;
	}

	const uri& get_url() const
	{
		return m_url;
	}

	void set_path(const std::string& path)
	{
		m_path = path;
		m_request = make_request(m_url, m_http_version);
	}

	void set_check_chunked(bool check = true)
	{
		m_check_chunked = check;
	}

	std::string make_request(uri url, const std::string& http_version)
	{
		std::ostringstream request;
		std::string host_and_port = url.get_host();
		if(!host_and_port.empty())
		{
			int port = url.get_port();
			if(port)
			{
				host_and_port.append(1, ':').append(std::to_string(port));
			}
		}
		request << "GET " << m_path;
		std::string query = url.get_query();
		if(!query.empty())
		{
			request << '?' << query;
		}
		request << " HTTP/" << http_version << "\r\n" << m_keep_alive << "User-Agent: sysdig\r\n";
		if(!host_and_port.empty())
		{
			request << "Host: " << host_and_port << "\r\n";
		}
		request << "Accept: */*\r\n";
		std::string creds = url.get_credentials();
		if(!creds.empty())
		{
			uri::decode(creds);
			std::istringstream is(creds);
			std::ostringstream os;
			base64::encoder().encode(is, os);
			request << "Authorization: Basic " << os.str() << "\r\n";
		}
		if(m_bt && !m_bt->get_token().empty())
		{
			request << "Authorization: Bearer " << m_bt->get_token() << "\r\n";
		}
		request << "\r\n";

		return request.str();
	}

	void set_id(const std::string& id)
	{
		m_id = id;
	}

	const std::string& get_id() const
	{
		return m_id;
	}

	void set_json_callback(json_callback_func_t f)
	{
		m_json_callback = f;
	}

	SSL* ssl_connection()
	{
		return m_ssl_connection;
	}

	bool wants_send() const
	{
		return m_wants_send;
	}

	void send_request()
	{
		m_wants_send = false; // no matter what happens, this is a one-shot
		if(m_request.empty())
		{
			throw sinsp_exception("Socket handler (" + m_id + ") send: request (empty).");
		}

		if(m_socket <= 0)
		{
			throw sinsp_exception("Socket handler (" + m_id + ") send: invalid socket.");
		}

		int iolen = 0;
		if(m_request.size())
		{
			g_logger.log("Socket handler (" + m_id + ") socket=" + std::to_string(m_socket) +
						 ", m_ssl_connection=" + std::to_string((int64_t)m_ssl_connection), sinsp_logger::SEV_TRACE);
			std::string req = m_request;
			time_t then; time(&then);
			while(req.size())
			{
				if(m_url.is_secure())
				{
					if(!m_ssl_connection)
					{
						throw sinsp_exception("Socket handler (" + m_id + ") send: SSL connection is null.");
					}
					iolen = SSL_write(m_ssl_connection, m_request.c_str(), m_request.size());
				}
				else
				{
					iolen = send(m_socket, m_request.c_str(), m_request.size(), 0);
				}
				if(iolen == static_cast<int>(req.size())) { break; }
				else if(iolen == 0 || errno == ENOTCONN || errno == EPIPE)
				{
					goto connection_closed;
				}
				else if(iolen < 0)
				{
					if(errno == ENOTCONN || errno == EPIPE)
					{
						goto connection_closed;
					}
					else if(errno != EAGAIN && errno != EWOULDBLOCK)
					{
						goto connection_error;
					}
					if(m_url.is_secure())
					{
						int err = SSL_get_error(m_ssl_connection, iolen);
						if(err != SSL_ERROR_WANT_WRITE && err != SSL_ERROR_WANT_READ)
						{
							goto connection_error;
						}
					}
				}
				else { req.erase(0, iolen); }
				time_t now; time(&now);
				if(difftime(now, then) > m_timeout_ms * 1000)
				{
					throw sinsp_exception("Socket handler (" + m_id + "): send timeout.");
				}
			}
		}
		else
		{
			throw sinsp_exception("Socket handler (" + m_id + ") request is empty.");
		}
		g_logger.log(m_request, sinsp_logger::SEV_TRACE);
		return;

		connection_error:
		{
			std::string err = strerror(errno);
			std::ostringstream os;
			os << "Socket handler (" << m_id << ") send_request(), connection [" << m_url.to_string(false) << "] error: " << err;
			if(m_url.is_secure())
			{
				std::string ssl_err = ssl_errors();
				if(!ssl_err.empty())
				{
					os << std::endl << "SSL error: " << ssl_err;
				}
			}
			throw sinsp_exception(os.str());
		}

		connection_closed:
		{
			std::ostringstream os;
			os << "Socket handler (" << m_id << ") send_request(), connection [" << m_url.to_string(false) << "] closed.";
			if(m_url.is_secure())
			{
				std::string ssl_err = ssl_errors();
				if(!ssl_err.empty())
				{
					os << std::endl << "SSL error: " << ssl_err;
				}
			}
			m_connecting = false;
			m_connected = false;
			throw sinsp_exception(os.str());
		}
	}

	void set_socket_option(int opt)
	{
		int flags = fcntl(m_socket, F_GETFL, 0);
		if(flags != -1)
		{
			fcntl(m_socket, F_SETFL, flags | opt);
		}
		else
		{
			throw sinsp_exception("Socket handler (" + m_id +
								  ") error while setting socket option (" +
								  std::to_string(opt) + "): " + strerror(errno));
		}
	}

	int get_all_data()
	{
		g_logger.log("Socket handler (" + m_id + ") Retrieving all data in blocking mode ...",
					 sinsp_logger::SEV_TRACE);
		ssize_t rec = 0;
		std::vector<char> buf(1024, 0);
		std::string data;
		bool data_received = false;
		int counter = 0;
		do
		{
			int count = 0;
			int ioret = 0;
			if(m_url.is_secure())
			{
				count = SSL_pending(m_ssl_connection);
			}
			else
			{
				ioret = ioctl(m_socket, FIONREAD, &count);
			}
			if(ioret >= 0 && count > 0)
			{
				data_received = true;
				buf.resize(count);
				if(m_url.is_secure())
				{
					rec = SSL_read(m_ssl_connection, &buf[0], buf.size());
				}
				else
				{
					rec = recv(m_socket, &buf[0], buf.size(), 0);
				}
				if(rec > 0)
				{
					data.append(buf.begin(), buf.begin() + rec);
				}
				else if(rec == 0)
				{
					throw sinsp_exception("Socket handler (" + m_id + "): Connection closed.");
				}
				else if(rec < 0)
				{
					throw sinsp_exception("Socket handler (" + m_id + "): " + strerror(errno));
				}
				//g_logger.log("Socket handler (" + m_id + ") received=" + std::to_string(rec) + "\n\n" + data + "\n\n", sinsp_logger::SEV_TRACE);
			}
			else
			{
				if(data_received && ++counter > 10)
				{
					break;
				}
				else
				{
					usleep(100);
				}
			}
		} while(true);
		if(data.size())
		{
			parse_http(data);
			process_json();
			return data.size();
		}
		return 0;
	}

	bool is_chunked_end_char(char c)
	{
		return c == '0' || c == '\r' || c == '\n';
	}

	void check_chunked_end(const std::string& data)
	{
		if(!m_check_chunked) { return; }
		if(m_chunked_end.size())
		{
			for(auto c : data)
			{
				if(!is_chunked_end_char(c))
				{
					m_chunked_end.clear();
					break;
				}
				else
				{
					m_chunked_end.append(1, c);
				}
			}
		}

		if(!m_chunked_end.size())
		{
			auto it = data.crbegin();
			for(; it != data.crend(); ++it)
			{
				if(!is_chunked_end_char(*it)) { return; }
				else { m_chunked_end.insert(0, 1, *it); }
			}
		}
	}

	void data_handling_error(const std::string& data, size_t nparsed)
	{
		std::ostringstream os;
		os << "Socket handler (" << m_id + ") an error occurred during http parsing. "
			"processed=" << nparsed << ", expected=" << data.size() << ", status_code=" <<
			std::to_string(m_http_parser->status_code) << ", http_errno=" <<
			std::to_string(m_http_parser->http_errno) << "data:" << std::endl << data;
		throw sinsp_exception(os.str());
	}

	void parse_http(const std::string& data)
	{
		size_t nparsed = http_parser_execute(m_http_parser, &m_http_parser_settings, data.c_str(), data.length());
		if(nparsed != data.size()) { data_handling_error(data, nparsed); }
	}

	void process_json()
	{
		if(m_json_filters.empty()) { add_json_filter("."); }
		bool handled = false;
		for(auto js = m_json.begin(); js != m_json.end();)
		{
			handled = false;
			for(auto it = m_json_filters.cbegin(); it != m_json_filters.cend(); ++it)
			{
				json_ptr_t pjson = try_parse(m_jq, *js, *it, m_id, m_url.to_string(false));
				if(pjson)
				{
					(m_obj.*m_json_callback)(pjson, m_id);
					handled = true;
					break;
				}
			}
			if(!handled)
			{
				g_logger.log("Socket handler: (" + m_id + ") JSON not handled, "
							 "discarding:\n" + *js, sinsp_logger::SEV_ERROR);
			}
			js = m_json.erase(js);
		}
	}

	int on_data()
	{
		bool is_error = false;

		if(!m_json_callback)
		{
			throw sinsp_exception("Socket handler (" + m_id + "): cannot parse data (callback is null).");
		}

		ssize_t iolen = 0;
		std::string data;
		try
		{
			do
			{
				errno = 0;
				if(m_url.is_secure())
				{
					iolen = static_cast<ssize_t>(SSL_read(m_ssl_connection, &m_buf[0], m_buf.size()));
				}
				else
				{
					iolen = recv(m_socket, &m_buf[0], m_buf.size(), 0);
				}
				m_sock_err = errno;
				g_logger.log(m_id + ' ' + m_url.to_string(false) + ", iolen=" +
							 std::to_string(iolen) + ", data=" + std::to_string(data.size()) + " bytes, "
							 "errno=" + std::to_string(m_sock_err) + " (" + strerror(m_sock_err) + ')',
							 sinsp_logger::SEV_TRACE);
				if(iolen > 0)
				{
					data.append(&m_buf[0], iolen <= static_cast<ssize_t>(m_buf.size()) ?
											static_cast<size_t>(iolen) : m_buf.size());
				}
				else if(iolen == 0 || m_sock_err == ENOTCONN || m_sock_err == EPIPE)
				{
					if(m_url.is_secure())
					{
						if(m_ssl_connection)
						{
							int sd = SSL_get_shutdown(m_ssl_connection);
							if(sd == 0)
							{
								g_logger.log("Socket handler (" + m_id + "): SSL zero bytes received, "
											 "but no shutdown state set for [" + m_url.to_string(false) + "]: ",
											 sinsp_logger::SEV_WARNING);
							}
							if(sd & SSL_RECEIVED_SHUTDOWN)
							{
								g_logger.log("Socket handler(" + m_id + "): SSL shutdown from [" +
											 m_url.to_string(false) + "]: ", sinsp_logger::SEV_TRACE);
							}
							if(sd & SSL_SENT_SHUTDOWN)
							{
								g_logger.log("Socket handler(" + m_id + "): SSL shutdown sent to [" +
											 m_url.to_string(false) + "]: ", sinsp_logger::SEV_TRACE);
							}
						}
						else
						{
							g_logger.log("Socket handler(" + m_id + "): SSL connection is null",
											 sinsp_logger::SEV_WARNING);
						}
					}
					goto connection_closed;
				}
				else if(iolen < 0)
				{
					if(m_sock_err == ENOTCONN || m_sock_err == EPIPE)
					{
						goto connection_closed;
					}
					else if(m_sock_err != EAGAIN && m_sock_err != EWOULDBLOCK)
					{
						goto connection_error;
					}
					if(m_url.is_secure())
					{
						int err = SSL_get_error(m_ssl_connection, iolen);
						if(err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
						{
							goto connection_error;
						}
					}
				}
			} while(iolen && m_sock_err != EAGAIN);
			if(data.size())
			{
				check_chunked_end(data);
				parse_http(data);
				if(m_chunked_end.find("0\r\n\r\n") != std::string::npos)
				{
					m_data_buf.clear();
					// In HTTP 1.1 connnections with chunked transfer, this socket may not be closed by server,
					// (K8s API server is an example of such behavior), in which case the chunked data will just
					// stop flowing. We can keep the good socket and resend the request instead of severing the
					// connection. The m_wants_send flag has to be checked by the caller and request re-sent, otherwise
					// this pipeline will remain idle. To force client-initiated socket close on chunked transfer end,
					// set the m_close_on_chunked_end flag to true (default).
					if(m_close_on_chunked_end) { return CONNECTION_CLOSED; }
					else { m_wants_send = true; }
				}
				else { process_json(); }
			}
		}
		catch(sinsp_exception& ex)
		{
			g_logger.log(std::string("Socket handler (" + m_id + ") data receive error [" +
						 m_url.to_string(false) + "]: ").append(ex.what()),
						 sinsp_logger::SEV_ERROR);
			return m_sock_err;
		}
		return 0;

	connection_error:
		is_error = true;

	connection_closed:
		if(m_url.is_secure())
		{
			std::string ssl_err = ssl_errors();
			if(!ssl_err.empty())
			{
				g_logger.log(ssl_err, sinsp_logger::SEV_ERROR);
			}
		}
		return is_error ? m_sock_err : CONNECTION_CLOSED;
	}

	static bool is_connection_closed(int val)
	{
		return val == CONNECTION_CLOSED;
	}

	void on_error(const std::string& /*err*/, bool /*disconnect*/)
	{
	}

	bool has_json_filter(const std::string& filter)
	{
		for(auto flt : m_json_filters)
		{
			if(flt == filter)
			{
				return true;
			}
		}
		return false;
	}

	void add_json_filter(const std::string& filter, const std::string& before_filter = "")
	{
		if(filter.empty())
		{
			throw sinsp_exception(std::string("Socket handler (") + m_id + "), "
							  "[" + m_url.to_string(false) + "] "
							  "attempt to add empty filter");
		}
		remove_json_filter(filter);
		if(before_filter.empty())
		{
			m_json_filters.push_back(filter);
			return;
		}
		else
		{
			auto it = m_json_filters.begin();
			for(; it != m_json_filters.end(); ++it)
			{
				if(*it == before_filter) { break; }
			}
			if(it != m_json_filters.end())
			{
				m_json_filters.insert(it, filter);
			}
			else
			{
				throw sinsp_exception(std::string("Socket handler (") + m_id + "), "
							  "[" + m_url.to_string(false) + "] "
							  "attempt to insert before non-existing filter");
			}
		}
	}

	void remove_json_filter(const std::string& filter)
	{
		for(auto it = m_json_filters.begin(); it != m_json_filters.end(); ++it)
		{
			if(*it == filter)
			{
				m_json_filters.erase(it);
				return;
			}
		}
	}

	void replace_json_filter(const std::string& from, const std::string& to)
	{
		for(auto it = m_json_filters.begin(); it != m_json_filters.end(); ++it)
		{
			if(*it == from)
			{
				*it = to;
				return;
			}
		}
		throw sinsp_exception(std::string("Socket handler (") + m_id + "), "
							  "[" + m_url.to_string(false) + "] "
							  "attempt to replace non-existing filter");
	}

	void print_filters(sinsp_logger::severity sev = sinsp_logger::SEV_DEBUG)
	{
		std::ostringstream filters;
		filters << std::endl << "Filters:" << std::endl;
		for(auto filter : m_json_filters)
		{
			filters << filter << std::endl;
		}
		g_logger.log("Socket handler (" + m_id + "), [" + m_url.to_string(false) + "]" + filters.str(), sev);
	}

	static json_ptr_t try_parse(json_query& jq, const std::string& json, const std::string& filter,
								const std::string& id, const std::string& url)
	{
		std::string filtered_json(json);
		if(!filter.empty())
		{
			if(jq.process(json, filter))
			{
				filtered_json = jq.result();
			}
			else
			{
				g_logger.log("Socket handler (" + id + "), [" + url + "] parsing error; " +
							 json + ", jq filter: <" + filter + '>', sinsp_logger::SEV_ERROR);
				return nullptr;
			}
		}
		json_ptr_t root(new Json::Value());
		try
		{
			if(Json::Reader().parse(filtered_json, *root))
			{
				/*
				if(g_logger.get_severity() >= sinsp_logger::SEV_TRACE)
				{
					g_logger.log("Socket handler (" + id + "), [" + url + "] "
								 "filtered JSON: " + json_as_string(*root),
								 sinsp_logger::SEV_TRACE);
				}
				*/
				return root;
			}
		}
		catch(...) { }
		g_logger.log("Socket handler (" + id + "), [" + url + "] parsing error; JSON: <" +
					 json + ">, jq filter: <" + filter + '>', sinsp_logger::SEV_ERROR);
		return nullptr;
	}

	// when connection is non-blocking and a socket
	// should not be polled until it is connected
	// this flag indicates readiness to be polled
	bool is_enabled() const
	{
		return m_enabled;
	}

	void enable(bool e = true)
	{
		m_enabled = e;
	}

	bool connection_error() const
	{
		return m_connection_error;
	}

	int get_socket_error()
	{
		socklen_t optlen = sizeof(m_sock_err);
		int ret = getsockopt(m_socket, SOL_SOCKET, SO_ERROR, &m_sock_err, &optlen);
		g_logger.log("Socket handler (" + m_id + ") getsockopt() ret=" +
						 std::to_string(ret) + ", m_sock_err=" + std::to_string(m_sock_err) +
						 " (" + strerror(m_sock_err) + ')',
						 sinsp_logger::SEV_TRACE);
		if(!ret) { return m_sock_err; }
		throw sinsp_exception("Socket handler (" + m_id + ") an error occurred "
					 "trying to obtain socket status while connecting to " +
					 m_url.to_string(false) + ": " + strerror(ret));
	}

private:

	typedef std::vector<char> password_vec_t;

	int wait(bool for_recv, long tout = 1000L)
	{
		struct timeval tv;
		tv.tv_sec = m_timeout_ms / 1000;
		tv.tv_usec = (m_timeout_ms % 1000) * 1000;

		fd_set infd, outfd, errfd;
		FD_ZERO(&infd);
		FD_ZERO(&outfd);
		FD_ZERO(&errfd);
		FD_SET(m_socket, &errfd);
		if(for_recv)
		{
			FD_SET(m_socket, &infd);
		}
		else
		{
			FD_SET(m_socket, &outfd);
		}

		return select(m_socket + 1, &infd, &outfd, &errfd, &tv);
	}

	bool send_ready()
	{
		struct timeval tv = {0};
		fd_set outfd;
		FD_ZERO(&outfd);
		FD_SET(m_socket, &outfd);
		int sel_ret = select(m_socket + 1, 0, &outfd, 0, &tv);
		if(sel_ret != 1) { return false; }
		int sock_ret = get_socket_error();
		if(!sock_ret) { return true; }
		return false;
	}

	bool recv_ready()
	{
		struct timeval tv = {0};
		fd_set infd;
		FD_ZERO(&infd);
		FD_SET(m_socket, &infd);
		return select(m_socket + 1, &infd, 0, 0, &tv) == 1;
	}

	bool socket_error()
	{
		struct timeval tv = {0};
		fd_set errfd;
		FD_ZERO(&errfd);
		FD_SET(m_socket, &errfd);
		return select(m_socket + 1, 0, 0, &errfd, &tv) == 1;
	}

	static int ssl_verify_callback(int preverify_ok, X509_STORE_CTX* ctx)
	{
		SSL* ssl = (SSL*)X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
		if(ssl)
		{
			char  buf[256] = {0};
			X509* err_cert = X509_STORE_CTX_get_current_cert(ctx);
			X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);

			if(preverify_ok && SSL_get_verify_result(ssl) == X509_V_OK)
			{
				g_logger.log("Socket handler SSL CA verified: " + std::string(buf),
							 sinsp_logger::SEV_DEBUG);
				return 1;
			}
			else
			{
				int err = X509_STORE_CTX_get_error(ctx);
				int depth = X509_STORE_CTX_get_error_depth(ctx);
				g_logger.log("Socket handler SSL CA verify error: num=" + std::to_string(err) +
							 ':' + X509_verify_cert_error_string(err) +
							 ":depth=" + std::to_string(depth) +
							 ':' + std::string(buf), sinsp_logger::SEV_ERROR);
				return 0;
			}
		}
		return 0;
	}

	static int ssl_no_verify_callback(int, X509_STORE_CTX* ctx)
	{
		g_logger.log("Socket handler SSL CA verification disabled, certificate accepted.",
					 sinsp_logger::SEV_DEBUG);
		return 1;
	}

	static int ssl_key_password_cb(char *buf, int size, int, void* pass)
	{
		if(pass)
		{
			std::memset(buf, 0, size);
			int pass_len = static_cast<int>(strlen((char*)pass));
			if(size < (pass_len) + 1) { return 0; }
			strncpy(buf, (const char*)pass, pass_len);
			return pass_len;
		}
		return 0;
	}

	std::string ssl_errors()
	{
		std::ostringstream os;
		if(m_url.is_secure())
		{
			char errbuf[256] = {0};
			unsigned long err;
			while((err = ERR_get_error()) != 0)
			{
				if(os.str().empty())
				{
					os << "Socket handler (" << m_id << ", "
						"socket=" << std::to_string(m_socket) << ") SSL errors:\n";
				}
				os << ERR_error_string(err, errbuf) << std::endl;
			}
		}
		return os.str();
	}

	void init_ssl_context(void)
	{
		if(!m_ssl_context)
		{
			SSL_library_init();
			SSL_load_error_strings();
			OpenSSL_add_all_algorithms();
			const SSL_METHOD* method = TLSv1_2_client_method();
			if(!method)
			{
				g_logger.log("Socket handler (" + m_id + "): Can't initalize SSL method\n" + ssl_errors(),
							 sinsp_logger::SEV_ERROR);
			}
			m_ssl_context = SSL_CTX_new(method);
			if(!m_ssl_context)
			{
				g_logger.log("Socket handler (" + m_id + "): Can't initalize SSL context\n" + ssl_errors(),
							 sinsp_logger::SEV_ERROR);
				return;
			}

			if(m_ssl)
			{
				if(m_ssl->verify_peer())
				{
					const std::string ca_cert = m_ssl->ca_cert();
					if(!ca_cert.empty() && !SSL_CTX_load_verify_locations(m_ssl_context, ca_cert.c_str(), 0))
					{
						throw sinsp_exception("Socket handler (" + m_id + "): "
											  "Can't load SSL CA certificate (" + ca_cert + ").\n" +
											  ssl_errors());
					}
					else if(ca_cert.empty())
					{
						throw sinsp_exception("Socket handler (" + m_id + "): "
											  "Invalid SSL CA certificate configuration "
											  "(Verify Peer enabled but no CA certificate specified).");
					}
					SSL_CTX_set_verify(m_ssl_context, SSL_VERIFY_PEER, ssl_verify_callback);
					g_logger.log("Socket handler (" + m_id + "): CA verify set to PEER", sinsp_logger::SEV_TRACE);
				}
				else
				{
					SSL_CTX_set_verify(m_ssl_context, SSL_VERIFY_NONE, ssl_no_verify_callback);
					g_logger.log("Socket handler (" + m_id + "): CA verify set to NONE", sinsp_logger::SEV_TRACE);
				}

				const std::string& cert = m_ssl->cert();
				if(!cert.empty())
				{
					if(SSL_CTX_use_certificate_file(m_ssl_context, cert.c_str(), SSL_FILETYPE_PEM) <= 0)
					{
						throw sinsp_exception("Socket handler (" + m_id + "): "
											  "Can't load SSL certificate  from " + cert + ".\n" +
											  ssl_errors());
					}
					else
					{
						g_logger.log("Socket handler (" + m_id + "): using SSL certificate from " + cert,
									 sinsp_logger::SEV_TRACE);
					}
					const std::string& key = m_ssl->key();
					if(!key.empty())
					{
						const std::string& pass = m_ssl->key_passphrase();
						if(!pass.empty())
						{
							m_ssl_key_pass.assign(pass.begin(), pass.end());
							m_ssl_key_pass.push_back('\0');
							SSL_CTX_set_default_passwd_cb_userdata(m_ssl_context, (void*)&m_ssl_key_pass[0]);
							SSL_CTX_set_default_passwd_cb(m_ssl_context, ssl_key_password_cb);
						}

						if(SSL_CTX_use_PrivateKey_file(m_ssl_context, key.c_str(), SSL_FILETYPE_PEM) <= 0)
						{
							throw sinsp_exception("Socket handler (" + m_id + "): "
											  "Can't load SSL private key from " + key + ".\n" +
											  ssl_errors());
						}
						else
						{
							g_logger.log("Socket handler (" + m_id + "): using SSL private key from " + key, sinsp_logger::SEV_TRACE);
						}

						if(!SSL_CTX_check_private_key(m_ssl_context))
						{
							throw sinsp_exception("Socket handler (" + m_id + "): "
											  "SSL private key (" + key + ") does not match public certificate (" + cert + ").\n" +
											  ssl_errors());
						}
						else
						{
							g_logger.log("Socket handler (" + m_id + "): SSL private key " + key + " matches public certificate " + cert,
										 sinsp_logger::SEV_TRACE);
						}
					}
					else
					{
						throw sinsp_exception("Socket handler (" + m_id + "): "
											  "Invalid SSL configuration: public certificate specified without private key.");
					}
				}
				else
				{
					g_logger.log("Socket handler (" + m_id + "): SSL public certificate not provided.", sinsp_logger::SEV_TRACE);
				}
			}
		}
	}

	void init_ssl_socket()
	{
		if(m_socket != -1 && !m_ssl_init_complete)
		{
			if(m_url.is_secure())
			{
				if(!m_ssl_context) { init_ssl_context(); }
				if(m_ssl_context)
				{
					m_ssl_connection = SSL_new(m_ssl_context);
					if(m_ssl_connection)
					{
						if(1 == SSL_set_fd(m_ssl_connection, m_socket))
						{
							m_ssl_init_complete = true;
						}
						else
						{
							throw sinsp_exception("Socket handler " + m_id + " (" + m_url.to_string(false) + ") "
							  "error assigning socket to SSL connection: " + ssl_errors());
						}
					}
					else
					{
						throw sinsp_exception("Socket handler " + m_id + " (" + m_url.to_string(false) + ") "
							  "error obtaining socket: " + ssl_errors());
					}
				}
				else
				{
					throw sinsp_exception("Socket handler " + m_id + " (" + m_url.to_string(false) + ") "
						  "SSL context error : " + ssl_errors());
				}
			}
		}
	}

	void create_socket()
	{
		int sock_type = SOCK_STREAM;
		if(!m_blocking)
		{
			sock_type |= SOCK_NONBLOCK;
		}
		if(m_socket < 0)
		{
			if(m_url.is_file())
			{
				m_socket = socket(PF_UNIX, sock_type, 0);
			}
			else
			{
				m_socket = socket(PF_INET, sock_type, 0);
			}
			if(m_socket < 0)
			{
				throw sinsp_exception("Socket handler " + m_id + " (" + m_url.to_string(false) + ") "
									  "error obtaining socket: " + strerror(errno));
			}
		}
	}

	bool check_connected()
	{
		if(!send_ready())
		{
			if(m_sock_err && m_sock_err != EINPROGRESS)
			{
				m_connection_error = true;
				throw sinsp_exception("Socket handler (" + m_id + ") an error occurred "
							 "while connecting to " + m_url.to_string(false) + ": " + strerror(m_sock_err));
			}
			else if(m_sock_err == EINPROGRESS)
			{
				m_connection_error = false;
				m_connecting = true;
				m_connected = false;
			}
			return false;
		}
		return true;
	}

	bool try_connect()
	{
		g_logger.log("Socket handler (" + m_id + ") try_connect() entry, m_connecting=" + std::to_string(m_connecting) +
						 ", m_connected=" + std::to_string(m_connected), sinsp_logger::SEV_TRACE);
		if(m_connected) { return true; }
		if(m_socket == -1)
		{
			create_socket();
		}

		if(!is_resolved())
		{
			if(!try_resolve())
			{
				return false;
			}
		}

		int ret = -1;
		if(m_connection_error)
		{
			return false;
		}
		else
		{
			if(!check_connected())
			{
				return false;
			}
		}

		g_logger.log("Socket handler (" + m_id + ") try_connect() middle, m_connecting=" + std::to_string(m_connecting) +
						 ", m_connected=" + std::to_string(m_connected), sinsp_logger::SEV_TRACE);
		if(!m_connected)
		{
			g_logger.log("Socket handler (" + m_id + ") connecting to " + m_url.to_string(false) +
						 " (socket=" + std::to_string(m_socket) + ')', sinsp_logger::SEV_DEBUG);
			if(!m_sa || !m_sa_len)
			{
				std::ostringstream os;
				os << m_sa;
				throw sinsp_exception("Socket handler (" + m_id + ") invalid state connecting to " +
							 m_url.to_string(false) + " (socket=" + std::to_string(m_socket) + "), "
							 "sa=" + os.str() + ", sa_len=" + std::to_string(m_sa_len));
			}
			if(!m_connect_called)
			{
				ret = connect(m_socket, m_sa, m_sa_len);
				m_connect_called = true;
				if(ret < 0 && errno != EINPROGRESS)
				{
					throw sinsp_exception("Error during conection attempt to " + m_url.to_string(false) +
										  " (socket=" + std::to_string(m_socket) +
										  ", error=" + std::to_string(errno) + "): " + strerror(errno));
				}
				else if(errno == EINPROGRESS)
				{
					m_connecting = true;
					m_connected = false;
					return false;
				}
			}
			else
			{
				if(get_socket_error() == EINPROGRESS)
				{
					m_connecting = true;
					m_connected = false;
					return false;
				}
			}
			if(m_url.is_secure())
			{
				if(!m_ssl_init_complete)
				{
					init_ssl_socket();
				}
				if(m_ssl_connection)
				{
					ret = SSL_connect(m_ssl_connection);
					if(ret == 1)
					{
						m_connecting = false;
						m_connected = true;
						g_logger.log("Socket handler (" + m_id + "): "
									 "SSL connected to " + m_url.get_host(),
									 sinsp_logger::SEV_INFO);
						g_logger.log("Socket handler (" + m_id + "): "
									 "SSL socket=" + std::to_string(m_socket) + ", "
									 "local port=" + std::to_string(get_local_port()),
									 sinsp_logger::SEV_DEBUG);
					}
					else
					{
						int err = SSL_get_error(m_ssl_connection, ret);
						switch(err)
						{
						case SSL_ERROR_NONE:             // 0
							break;
						case SSL_ERROR_SSL:              // 1
							throw sinsp_exception(ssl_errors());
						case SSL_ERROR_WANT_READ:        // 2
						case SSL_ERROR_WANT_WRITE:       // 3
							return false;
						case SSL_ERROR_WANT_X509_LOOKUP: // 4
							break;
						case SSL_ERROR_SYSCALL:          // 5
							throw sinsp_exception("Socket handler (" + m_id + "), error "  + std::to_string(err) +
												  " (" + strerror(errno) + ") while connecting to " +
												  m_url.get_host() + ':' + std::to_string(m_url.get_port()));
						case SSL_ERROR_ZERO_RETURN:      // 6
							cleanup();
							throw sinsp_exception("Socket handler (" + m_id + "), "
												  "error (connection closed) while connecting to " +
												  m_url.get_host() + ':' + std::to_string(m_url.get_port()));
						case SSL_ERROR_WANT_CONNECT:     // 7
							throw sinsp_exception("Socket handler (" + m_id + "), "
												  "error (the operation failed while attempting to connect "
												  "the transport) while connecting to " +
												  m_url.get_host() + ':' + std::to_string(m_url.get_port()));
						case SSL_ERROR_WANT_ACCEPT:      // 8
							throw sinsp_exception("Socket handler (" + m_id + "), "
												  "error (the operation failed while attempting to accept a"
												  " connection from the transport) while connecting to " +
												  m_url.get_host() + ':' + std::to_string(m_url.get_port()));
						}
					}
				}
				else
				{
					throw sinsp_exception("Socket handler (" + m_id + "): " + m_url.to_string(false) +
										" SSL connection is null (" + strerror(errno) + ')');
				}
			}

			g_logger.log("Socket handler (" + m_id + "): Connected: socket=" + std::to_string(m_socket) +
						 ", collecting data from " + m_url.to_string(false) + m_path, sinsp_logger::SEV_DEBUG);

			if(m_url.is_secure() && m_ssl && m_ssl->verify_peer())
			{
				if(SSL_get_peer_certificate(m_ssl_connection))
				{
					long err = SSL_get_verify_result(m_ssl_connection);
					if(err != X509_V_OK &&
						err != X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT &&
						err != X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)
					{
						throw sinsp_exception("Socket handler (" + m_id + "): " + m_url.to_string(false) +
											  " server certificate verification failed.");
					}
				}
			}
			m_connection_error = false;
			m_connecting = false;
			m_connected = true;
		}
		return true;
	}

	bool is_resolved() const
	{
		return (!m_address.empty() && m_sa && m_sa_len) || m_url.is_file();
	}

	bool try_resolve()
	{
		if(is_resolved())
		{
			return true;
		}
		else
		{
			if(inet_aton(m_url.get_host().c_str(), &m_serv_addr.sin_addr)) // IP address provided
			{
				m_address = m_url.get_host();
			}
			else // name provided, resolve to IP address
			{
				m_serv_addr = {0};
				int ret = 0;
				if(!m_dns_reqs) // first call, call async resolver
				{
					g_logger.log("Socket handler (" + m_id + ") resolving " + m_url.get_host(),
								 sinsp_logger::SEV_TRACE);
					m_dns_reqs = (struct gaicb**)calloc(1, sizeof(struct gaicb*));
					m_dns_reqs[0] = (struct gaicb*)calloc(1, sizeof(struct gaicb));
					m_dns_reqs[0]->ar_name = strdup(m_url.get_host().c_str());
					ret = getaddrinfo_a(GAI_NOWAIT, &m_dns_reqs[0], 1, NULL);
					if(ret)
					{
						throw sinsp_exception("Socket handler (" + m_id + "): " + m_url.get_host() +
									 " getaddrinfo_a() failed: " + gai_strerror(ret));
					}
					return false;
				}
				else // rest of the calls, try to get resolver result
				{
					g_logger.log("Socket handler (" + m_id + ") checking resolve for " + m_url.get_host(),
								 sinsp_logger::SEV_TRACE);
					ret = gai_error(m_dns_reqs[0]);
					g_logger.log("Socket handler (" + m_id + ") gai_error=" + std::to_string(ret),
								 sinsp_logger::SEV_TRACE);
					if(!ret)
					{
						if(m_dns_reqs && m_dns_reqs[0] && m_dns_reqs[0]->ar_result)
						{
							for (struct addrinfo* ai = m_dns_reqs[0]->ar_result; ai; ai = ai->ai_next)
							{
								if(ai->ai_addrlen && ai->ai_addr && ai->ai_addr->sa_family == AF_INET)
								{
									struct sockaddr_in* saddr = (struct sockaddr_in*)ai->ai_addr;
									if(saddr->sin_addr.s_addr)
									{
										m_serv_addr.sin_addr.s_addr = saddr->sin_addr.s_addr;
										m_address = inet_ntoa(saddr->sin_addr);
										g_logger.log("Socket handler (" + m_id + "): " + m_url.get_host() +
													 " resolved to " + m_address, sinsp_logger::SEV_TRACE);
										dns_cleanup();
										break;
									}
								}
							}
							if(!m_serv_addr.sin_addr.s_addr)
							{
								g_logger.log("Socket handler (" + m_id + "): " + m_url.get_host() +
											 " address not resolved yet.", sinsp_logger::SEV_TRACE);
								return false;
							}
						}
						else
						{
							throw sinsp_exception("Socket handler (" + m_id + "): " + m_url.get_host() +
												  ", resolver request is NULL.");
						}
					}
					else
					{
						switch(ret)
						{
							case EAI_AGAIN:
							case EAI_INPROGRESS:
								g_logger.log("Socket handler (" + m_id + ") [" + m_url.get_host() + "]: " +
											 gai_strerror(ret), sinsp_logger::SEV_DEBUG);
								break;
							case EAI_SYSTEM:
								g_logger.log("Socket handler (" + m_id + ") [" + m_url.get_host() + "]: " +
											 ", resolver error: " + gai_strerror(ret) +
											 ", system error: " + strerror(errno), sinsp_logger::SEV_ERROR);
								break;
							default:
								g_logger.log("Socket handler (" + m_id + ") [" + m_url.get_host() + "]: " +
											 ", resolver error: " + gai_strerror(ret),
											 sinsp_logger::SEV_ERROR);
						}
						return false;
					}
				}
			}
		}
		m_serv_addr.sin_family = AF_INET;
		m_serv_addr.sin_port = htons(m_url.get_port());
		m_sa = (sockaddr*)&m_serv_addr;
		m_sa_len = sizeof(struct sockaddr_in);
		return true;
	}

	void connect_socket()
	{
		if(!m_sa || !m_sa_len)
		{
			if(m_url.is_file())
			{
				if(m_url.get_path().length() > sizeof(m_file_addr.sun_path) - 1)
				{
					throw sinsp_exception("Invalid address (too long): [" + m_url.get_path() + ']');
				}
				m_file_addr.sun_family = AF_UNIX;
				strncpy(m_file_addr.sun_path, m_url.get_path().c_str(), m_url.get_path().length());
				m_file_addr.sun_path[sizeof(m_file_addr.sun_path) - 1]= '\0';
				m_sa = (sockaddr*)&m_file_addr;
				m_sa_len = sizeof(struct sockaddr_un);
			}
			else if(m_url.is("https") || m_url.is("http"))
			{
				try_resolve();
			}
			else
			{
				throw sinsp_exception("Socket handler (" + m_id + "): " +
									  m_url.get_scheme() + " protocol not supported.");
			}
		}
		try_connect();
	}

	std::string get_local_address()
	{
		struct sockaddr_in local_address;
		socklen_t address_length = sizeof(local_address);
		getsockname(m_socket, (struct sockaddr*)&local_address, &address_length);
		return std::string(inet_ntoa(local_address.sin_addr));
	}

	int get_local_port()
	{
		struct sockaddr_in local_address;
		socklen_t address_length = sizeof(local_address);
		getsockname(m_socket, (struct sockaddr*)&local_address, &address_length);
		return (int) ntohs(local_address.sin_port);
	}

	void close_socket()
	{
		if(m_socket != -1)
		{
			g_logger.log("Socket handler (" + m_id + ") closing connection to " +
						 m_url.to_string(false) + m_path, sinsp_logger::SEV_DEBUG);
			int ret = close(m_socket);
			if(ret < 0)
			{
				g_logger.log("Socket handler (" + m_id + ") connection [" +
							 m_url.to_string(false) + m_path + "] error closing socket: " +
							 strerror(errno), sinsp_logger::SEV_ERROR);
			}
			m_socket = -1;
		}
		m_enabled = false;
		m_connected = false;
		m_connecting = false;
		m_connect_called = true;
	}

	bool dns_cleanup(struct gaicb** dns_reqs)
	{
		if(dns_reqs && dns_reqs[0])
		{
			int ret = gai_cancel(dns_reqs[0]);
			int err = gai_error(dns_reqs[0]);
			if(ret == EAI_ALLDONE || err == EAI_CANCELED)
			{
				if(dns_reqs[0]->ar_result)
				{
					freeaddrinfo(dns_reqs[0]->ar_result);
				}
				if(dns_reqs[0]->ar_name)
				{
					free((void*)dns_reqs[0]->ar_name);
				}
				free(dns_reqs[0]);
				dns_reqs[0] = 0;
				free(dns_reqs);
				return true;
			}
			else if(err == EAI_INPROGRESS || err == EAI_AGAIN)
			{
				std::string errstr = (err == EAI_INPROGRESS ) ?
									"processing in progress" :
									"resources temporarily unavailable";
				g_logger.log("Socket handler (" + m_id + ") connection [" + m_url.to_string(false) + "], "
							 " cancelling DNS request postponed (" + errstr + ")"
							 "\n err: (" + std::to_string(err) + ") " + gai_strerror(err),
							 sinsp_logger::SEV_DEBUG);
				return false;
			}
			else
			{
				g_logger.log("Socket handler (" + m_id + ") connection [" + m_url.to_string(false) + "], "
							 "error canceling DNS request"
							 "\n ret: (" + std::to_string(ret) + ") " + gai_strerror(ret) +
							 "\n err: (" + std::to_string(err) + ") " + gai_strerror(err),
							 sinsp_logger::SEV_ERROR);
				return false;
			}
		}
		return true;
	}

	void dns_cleanup()
	{
		for(dns_list_t::iterator it = m_pending_dns_reqs.begin(); it != m_pending_dns_reqs.end();)
		{
			if(dns_cleanup(*it))
			{
				it = m_pending_dns_reqs.erase(it);
				g_logger.log("Socket handler: postponed canceling of DNS request succeeded, number of pending "
							 "cancelation requests: " + std::to_string(m_pending_dns_reqs.size()),
							 sinsp_logger::SEV_TRACE);
			}
			else { ++it; }
		}

		std::size_t pending_reqs = m_pending_dns_reqs.size();
		if(pending_reqs)
		{
			g_logger.log("Socket handler: number of pending DNS cancelation requests is " + std::to_string(pending_reqs),
						 (pending_reqs > 10) ? sinsp_logger::SEV_WARNING : sinsp_logger::SEV_TRACE);
		}

		if(dns_cleanup(m_dns_reqs))
		{
			m_dns_reqs = 0;
		}
		else // store for postponed canceling
		{
			m_pending_dns_reqs.push_back(m_dns_reqs);
		}
	}

	void ssl_cleanup()
	{
		SSL_free(m_ssl_connection);
		m_ssl_connection = 0;
		SSL_CTX_free(m_ssl_context);
		m_ssl_context = 0;
	}

	void cleanup()
	{
		free(m_http_parser);
		close_socket();
		dns_cleanup();
		ssl_cleanup();
	}

	struct http_parser_data
	{
		std::string*              m_data_buf = nullptr;
		std::vector<std::string>* m_json = nullptr;
	};

	static int http_body_callback(http_parser* parser, const char* data, size_t len)
	{
		if(data && len)
		{
			if(parser && parser->data)
			{
				http_parser_data* parser_data = (http_parser_data*) parser->data;
				if(parser_data->m_data_buf && parser_data->m_json)
				{
					parser_data->m_data_buf->append(data, len);
					std::string::size_type pos = parser_data->m_data_buf->find('\n');
					while(pos != std::string::npos)
					{
						parser_data->m_json->push_back(parser_data->m_data_buf->substr(0, pos));
						parser_data->m_data_buf->erase(0, pos + 1);
						pos = parser_data->m_data_buf->find('\n');
					}
				}
				else { throw sinsp_exception("Socket handler: http or json buffer null."); }
			}
			else { throw sinsp_exception("Socket handler: parser or data null."); }
		}
		return 0;
	}

	void init_http_parser()
	{
		http_parser_settings_init(&m_http_parser_settings);
		m_http_parser_settings.on_body = &socket_data_handler<T>::http_body_callback;
		m_http_parser = (http_parser *)std::malloc(sizeof(http_parser));
		if(m_http_parser)
		{
			m_http_parser_data.m_data_buf = &m_data_buf;
			m_http_parser_data.m_json = &m_json;
			http_parser_init(m_http_parser, HTTP_RESPONSE);
			m_http_parser->data = &m_http_parser_data;
		}
		else
		{
			throw sinsp_exception("Socket handler: cannot create http parser.");
		}
	}

	typedef std::deque<struct gaicb**> dns_list_t;

	T&                       m_obj;
	std::string              m_id;
	uri                      m_url;
	std::string              m_keep_alive;
	std::string              m_path;
	std::string              m_address;
	bool                     m_connecting = false;
	bool                     m_connected = false;
	bool                     m_connect_called = false;
	bool                     m_connection_error = false;
	bool                     m_enabled = false;
	int                      m_socket = -1;
	bool                     m_blocking = false;
	std::vector<char>        m_buf;
	int                      m_sock_err = 0;
	struct gaicb**           m_dns_reqs = nullptr;
	static dns_list_t        m_pending_dns_reqs;
	ssl_ptr_t                m_ssl;
	bt_ptr_t                 m_bt;
	long                     m_timeout_ms;
	json_callback_func_t     m_json_callback = nullptr;
	std::string              m_data_buf;
	std::string              m_request;
	std::string              m_http_version;
	std::vector<std::string> m_json_filters;
	std::vector<std::string> m_json;
	json_query               m_jq;
	bool                     m_ssl_init_complete = false;
	SSL_CTX*                 m_ssl_context = nullptr;
	SSL*                     m_ssl_connection = nullptr;
	password_vec_t           m_ssl_key_pass;
	struct sockaddr_un       m_file_addr = {0};
	struct sockaddr_in       m_serv_addr = {0};
	struct sockaddr*         m_sa = 0;
	socklen_t                m_sa_len = 0;
	std::string::size_type   m_content_length = std::string::npos;
	std::string              m_chunked_end;
	bool                     m_check_chunked = false;
	bool                     m_close_on_chunked_end = true;
	bool                     m_wants_send = false;
	http_parser_settings     m_http_parser_settings;
	http_parser*             m_http_parser = nullptr;
	http_parser_data         m_http_parser_data;
};

template <typename T>
const std::string socket_data_handler<T>::HTTP_VERSION_10 = "1.0";
template <typename T>
const std::string socket_data_handler<T>::HTTP_VERSION_11 = "1.1";
template <typename T>
typename socket_data_handler<T>::dns_list_t socket_data_handler<T>::m_pending_dns_reqs;

#endif // HAS_CAPTURE
