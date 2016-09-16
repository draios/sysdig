//
// socket_collector.h
//

#pragma once

#ifdef HAS_CAPTURE

#include "uri.h"
#include "json/json.h"
#define BUFFERSIZE 512 // b64 needs this macro
#include "b64/encode.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "sinsp_auth.h"
#include "json_query.h"
#include <unistd.h>
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

	socket_data_handler(T& obj,
						const std::string& id,
						const std::string& url,
						const std::string& path = "",
						const std::string& http_version = HTTP_VERSION_11,
						int timeout_ms = 1000L,
						ssl_ptr_t ssl = 0,
						bt_ptr_t bt = 0):
		m_obj(obj),
		m_id(id),
		m_url(url),
		m_path(path.empty() ? m_url.get_path() : path),
		m_ssl(ssl),
		m_bt(bt),
		m_timeout_ms(timeout_ms),
		m_request(make_request(m_url, http_version)),
		m_http_version(http_version),
		m_json_begin("\r\n{"),
		m_json_end(m_http_version == HTTP_VERSION_10 ? "}\r\n" : "}\r\n0")
	{
		g_logger.log(std::string("Creating Socket handler object for (" + id + ") [" + url + ']'), sinsp_logger::SEV_DEBUG);
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

	const uri& get_url() const
	{
		return m_url;
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
		request << " HTTP/" << http_version << "\r\nConnection: Keep-Alive\r\nUser-Agent: sysdig\r\n";
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

	void send_request()
	{
		if(m_request.empty())
		{
			throw sinsp_exception("Socket handler (" + m_id + ") send: request (empty).");
		}

		if(m_socket < 0)
		{
			throw sinsp_exception("Socket handler (" + m_id + ") send: invalid socket.");
		}

		int iolen = 0;
		if(m_request.size())
		{
			std::string req = m_request;
			time_t then; time(&then);
			while(req.size())
			{
				if(m_url.is_secure())
				{
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
			os << "Socket handler (" << m_id << ") connection [" << m_url.to_string(false) << "] error: " << err;
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
			os << "Socket handler (" << m_id << ") connection [" << m_url.to_string(false) << "] closed.";
			if(m_url.is_secure())
			{
				std::string ssl_err = ssl_errors();
				if(!ssl_err.empty())
				{
					os << std::endl << "SSL error: " << ssl_err;
				}
			}
			m_connected = false;
			throw sinsp_exception(os.str());
		}
	}

	bool on_data()
	{
		std::string error_desc;

		if(!m_json_callback)
		{
			throw sinsp_exception("Socket handler (" + m_id + "): cannot parse data (callback is null).");
		}

		size_t iolen = 0;
		std::vector<char> buf;
		std::string data;

		try
		{
			int loop_counter = 0;
			do
			{
				size_t iolen = 0;
				int count = 0;
				int ioret = 0;
				// TODO: suboptimal for SSL, there will always be much more data availability
				//       indicated than the amount of available application data
				ioret = ioctl(m_socket, FIONREAD, &count); 
				g_logger.log(m_id + ' ' + m_url.to_string(false) + " loop_counter=" + std::to_string(loop_counter) +
							 ", ioret=" + std::to_string(ioret) + ", count=" + std::to_string(count),
							 sinsp_logger::SEV_TRACE);
				if(ioret >= 0 && count > 0)
				{
					if(count > static_cast<int>(buf.size()))
					{
						buf.resize(count);
					}
					if(m_url.is_secure())
					{
						iolen = SSL_read(m_ssl_connection, &buf[0], count);
					}
					else
					{
						iolen = recv(m_socket, &buf[0], count, 0);
					}
					g_logger.log(m_id + ' ' + m_url.to_string(false) + " loop_counter=" + std::to_string(loop_counter) +
								", iolen=" + std::to_string(iolen), sinsp_logger::SEV_TRACE);
					if(iolen > 0)
					{
						data.append(&buf[0], iolen <= buf.size() ? iolen : buf.size());
					}
					else if(iolen == 0 || errno == ENOTCONN || errno == EPIPE)
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
							if(err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
							{
								goto connection_error;
							}
						}
					}
				}
				else
				{
					if(ioret < 0) { goto connection_error; }
					else if(loop_counter == 0 && count == 0) { goto connection_closed; }
					break;
				}
				++loop_counter;
			} while(iolen && errno != EAGAIN);
			if(data.size())
			{
				extract_data(data);
			}
		}
		catch(sinsp_exception& ex)
		{
			g_logger.log(std::string("Socket handler (" + m_id + ") data receive error [" +
						 m_url.to_string(false) + "]: ").append(ex.what()),
						 sinsp_logger::SEV_ERROR);
			return false;
		}
		return true;

	connection_error:
		{
			error_desc = "error";
		}

	connection_closed:
		{
			if(error_desc.empty())
			{
				error_desc = "closed";
				m_connected = false;
			}
			g_logger.log("Socket handler (" + m_id + ") connection [" + m_url.to_string(false) + "] " +
						 error_desc + " (" + (errno ? strerror(errno) : "no error") + ")",
						 sinsp_logger::SEV_ERROR);
			if(m_url.is_secure())
			{
				std::string ssl_err = ssl_errors();
				if(!ssl_err.empty())
				{
					g_logger.log(ssl_err, sinsp_logger::SEV_ERROR);
				}
			}
		}
		cleanup();
		m_socket = -1;
		return false;
	}

	void on_error(const std::string& /*err*/, bool /*disconnect*/)
	{
		m_connected = false;
	}

	void set_json_begin(const std::string& b)
	{
		m_json_begin = b;
	}

	const std::string& get_json_begin() const
	{
		return m_json_begin;
	}

	void set_json_end(const std::string& e)
	{
		m_json_end = e;
	}

	const std::string& get_json_end() const
	{
		return m_json_end;
	}

	void add_json_filter(const std::string& filter)
	{
		m_json_filters.push_back(filter);
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
		for(auto it = m_json_filters.cbegin(); it != m_json_filters.cend(); ++it)
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

	static json_ptr_t try_parse(json_query& jq, const std::string& json, const std::string& filter,
								const std::string& id, const std::string& url)
	{
		std::string filtered_json;
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

private:

	typedef std::vector<char> password_vec_t;

	bool purge_chunked_markers(std::string& data)
	{
		std::string::size_type pos = data.find("}\r\n0");
		if(pos != std::string::npos)
		{
			data = data.substr(0, pos);
		}

		const std::string nl = "\r\n";
		std::string::size_type begin, end;
		while((begin = data.find(nl)) != std::string::npos)
		{
			end = data.find(nl, begin + 2);
			if(end != std::string::npos)
			{
				data.erase(begin, end + 2 - begin);
			}
			else // newlines must come in pairs
			{
				return false;
			}
		}
		return true;
	}

	void handle_json(std::string::size_type end_pos, bool chunked)
	{
		if(end_pos != std::string::npos)
		{
			if(m_data_buf.length() >= end_pos + 1)
			{
				std::string json = m_data_buf.substr(0, end_pos + 1);
				if(m_data_buf.length() > end_pos + 1)
				{
					m_data_buf = m_data_buf.substr(end_pos + 2);
				}
				else
				{
					m_data_buf.clear();
					m_content_length = std::string::npos;
				}
				if(json.size())
				{
					if(chunked && !purge_chunked_markers(m_data_buf))
					{
						g_logger.log("Socket handler (" + m_id + "): Invalid JSON data detected (chunked transfer).",
									 sinsp_logger::SEV_ERROR);
						(m_obj.*m_json_callback)(nullptr, m_id);
					}
					else
					{
						g_logger.log("Socket handler (" + m_id + "): invoking callback.", sinsp_logger::SEV_TRACE);
						for(auto it = m_json_filters.cbegin(); it != m_json_filters.cend(); ++it)
						{
							json_ptr_t pjson = try_parse(m_jq, json, *it, m_id, m_url.to_string(false));
							if(pjson)
							{
								(m_obj.*m_json_callback)(pjson, m_id);
								return;
							}
						}
					}
					g_logger.log("Socket handler (" + m_id + ") " + m_url.to_string(false) + ": "
								 "An error occurred while handling JSON.",
								 sinsp_logger::SEV_ERROR);
					g_logger.log(json, sinsp_logger::SEV_TRACE);
				}
			}
		}
	}

	bool detect_chunked_transfer(const std::string& data)
	{
		if(m_content_length == std::string::npos)
		{
			std::string::size_type cl_pos = data.find("Content-Length:");
			if(cl_pos != std::string::npos)
			{
				std::string::size_type nl_pos = data.find("\r\n", cl_pos);
				if(nl_pos != std::string::npos)
				{
					cl_pos += std::string("Content-Length:").length();
					std::string cl = data.substr(cl_pos, nl_pos - cl_pos);
					long len = strtol(cl.c_str(), NULL, 10);
					if(len == 0L || len == LONG_MAX || len == LONG_MIN || errno == ERANGE)
					{
						(m_obj.*m_json_callback)(nullptr, m_id);
						m_data_buf.clear();
						g_logger.log("Socket handler (" + m_id + "): Invalid HTTP content length from [: " + m_url.to_string(false) + ']' +
								 std::to_string(len), sinsp_logger::SEV_ERROR);
						return false;
					}
					else
					{
						m_content_length = static_cast<std::string::size_type>(len);
					}
				}
			}
		}
		return true;
	}

	void extract_data(std::string& data)
	{
		//g_logger.log(data,sinsp_logger::SEV_DEBUG);
		g_logger.log(m_id + ' ' + m_url.to_string(false) + ":\n\n" + data + "\n\n", sinsp_logger::SEV_TRACE);
		if(data.empty()) { return; }
		if(!detect_chunked_transfer(data))
		{
			g_logger.log("Socket handler (" + m_id + ") " + m_url.to_string(false) + ": "
						 "An error occurred while detecting chunked transfer.",
						 sinsp_logger::SEV_ERROR);
			return;
		}

		if(m_data_buf.empty()) { m_data_buf = data; }
		else { m_data_buf.append(data); }
		std::string::size_type pos = m_data_buf.find(m_json_begin);
		if(pos != std::string::npos) // JSON begin
		{
			m_data_buf = m_data_buf.substr(pos + 2);
		}
		else if(m_data_buf[0] == '{') // docker HTTP stream does this
		{
			pos = 0;
		}
		bool chunked = (m_content_length == std::string::npos);
		if(chunked)
		{
			std::string::size_type end = std::string::npos;
			while(true)
			{
				end = m_data_buf.find(m_json_end);
				if(end == std::string::npos) { break; }
				g_logger.log("Socket handler (" + m_id + ") " + m_url.to_string(false) + ": "
							 "found JSON end, handling JSON", sinsp_logger::SEV_TRACE);
				handle_json(end, true);
			}
		}
		else if (m_data_buf.length() >= m_content_length)
		{
			handle_json(m_data_buf.length() - 1, false);
		}
		return;
	}

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
		return select(m_socket + 1, 0, &outfd, 0, &tv) == 1;
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
					os << "Socket handler (" + m_id + ", socket=" + std::to_string(m_socket) + ") SSL errors:\n";
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
				g_logger.log("Socket handler (" + m_id + "): Can't initalize SSL method\n" + ssl_errors(), sinsp_logger::SEV_ERROR);
			}
			m_ssl_context = SSL_CTX_new(method);
			if(!m_ssl_context)
			{
				g_logger.log("Socket handler (" + m_id + "): Can't initalize SSL context\n" + ssl_errors(), sinsp_logger::SEV_ERROR);
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
											  "Invalid SSL CA certificate configuration (Verify Peer enabled but no CA certificate specified).");
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
						g_logger.log("Socket handler (" + m_id + "): using SSL certificate from " + cert, sinsp_logger::SEV_TRACE);
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
		if(m_socket < 0)
		{
			if(m_url.is_file())
			{
				m_socket = socket(PF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
			}
			else
			{
				m_socket = socket(PF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
			}
			if(m_socket < 0)
			{
				throw sinsp_exception("Socket handler " + m_id + " (" + m_url.to_string(false) + ") "
									  "error obtaining socket: " + strerror(errno));
			}
		}
	}

	bool try_connect()
	{
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
		else if(m_connecting)
		{
			if(!send_ready()) { return false; }
		}
		else
		{
			g_logger.log("Socket handler (" + m_id + ") connecting to " + m_address +
						 " (socket=" + std::to_string(m_socket) + ')', sinsp_logger::SEV_DEBUG);
			if(!m_sa || !m_sa_len)
			{
				std::ostringstream os;
				os << m_sa;
				throw sinsp_exception("Socket handler (" + m_id + ") invalid state connecting to " +
							 m_address + " (socket=" + std::to_string(m_socket) + "), "
							 "sa=" + os.str() + ", sa_len=" + std::to_string(m_sa_len));
			}
			ret = connect(m_socket, m_sa, m_sa_len);
			if(ret < 0 && errno != EINPROGRESS)
			{
				g_logger.log("Error during conection attempt to " + m_address +
									  " (socket=" + std::to_string(m_socket) +
									  ", error=" + std::to_string(errno) + "): " + strerror(errno),
									  sinsp_logger::SEV_ERROR);
				m_connection_error = true;
			}
			else if(errno == EINPROGRESS)
			{
				m_connecting = true;
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
				throw sinsp_exception("Socket handler (" + m_id + "): " + m_address +
									" SSL connection is null (" + strerror(errno) + ')');
			}
		}

		g_logger.log("Socket handler (" + m_id + "): Connected: socket=" + std::to_string(m_socket) +
					 ", collecting data from " + m_url.to_string(false), sinsp_logger::SEV_DEBUG);

		if(m_url.is_secure() && m_ssl && m_ssl->verify_peer())
		{
			if(SSL_get_peer_certificate(m_ssl_connection))
			{
				long err = SSL_get_verify_result(m_ssl_connection);
				if(err != X509_V_OK &&
					err != X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT &&
					err != X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)
				{
					throw sinsp_exception("Socket handler (" + m_id + "): " + m_address +
										  " server certificate verification failed.");
				}
			}
		}
		m_connecting = false;
		m_connected = true;
		return true;
	}

	bool is_resolved() const
	{
		return !m_address.empty() && m_sa && m_sa_len;
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
					g_logger.log("Socket handler (" + m_id + ") resolving " + m_url.get_host(), sinsp_logger::SEV_TRACE);
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
					g_logger.log("Socket handler (" + m_id + ") checking resolve for " + m_url.get_host(), sinsp_logger::SEV_TRACE);
					ret = gai_error(m_dns_reqs[0]);
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
										g_logger.log("Socket handler (" + m_id + "): " + m_url.get_host() + " resolved to " + m_address,
															 sinsp_logger::SEV_TRACE);
										dns_cleanup();
										break;
									}
								}
							}
							if(!m_serv_addr.sin_addr.s_addr)
							{
								g_logger.log("Socket handler (" + m_id + "): " + m_url.get_host() + " address not resolved yet.",
											 sinsp_logger::SEV_TRACE);
								return false;
							}
						}
						else
						{
							throw sinsp_exception("Socket handler (" + m_id + "): " + m_url.get_host() + ", resolver request is NULL.");
						}
					}
					else
					{
						switch(ret)
						{
							case EAI_AGAIN:
							case EAI_INPROGRESS:
								g_logger.log("Socket handler (" + m_id + ") [" + m_url.get_host() + "]: " + gai_strerror(ret),
											 sinsp_logger::SEV_DEBUG);
								break;
							case EAI_SYSTEM:
								g_logger.log("Socket handler (" + m_id + "): " + m_url.get_host() + ", resolver error: " + gai_strerror(ret) +
											 ", system error: " + strerror(errno), sinsp_logger::SEV_ERROR);
								break;
							default:
								g_logger.log("Socket handler (" + m_id + "): " + m_url.get_host() + ", resolver error: " + gai_strerror(ret),
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
			g_logger.log("Socket handler (" + m_id + ") closing connection to " + m_url.to_string(false),
					 sinsp_logger::SEV_DEBUG);
			int ret = close(m_socket);
			if(ret < 0)
			{
				g_logger.log("Socket handler (" + m_id + ") connection [" + m_url.to_string(false) + "] "
							 "error closing socket: " + strerror(errno), sinsp_logger::SEV_ERROR);
			}
			m_socket = -1;
		}
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
		close_socket();
		dns_cleanup();
		ssl_cleanup();
	}

	typedef std::deque<struct gaicb**> dns_list_t;

	T&                       m_obj;
	std::string              m_id;
	uri                      m_url;
	std::string              m_path;
	std::string              m_address;
	bool                     m_connecting = false;
	bool                     m_connected = false;
	bool                     m_connection_error = false;
	bool                     m_enabled = false;
	int                      m_socket = -1;
	struct gaicb**           m_dns_reqs = nullptr;
	static dns_list_t        m_pending_dns_reqs;
	ssl_ptr_t                m_ssl;
	bt_ptr_t                 m_bt;
	long                     m_timeout_ms;
	json_callback_func_t     m_json_callback = nullptr;
	std::string              m_data_buf;
	std::string              m_request;
	std::string              m_http_version;
	std::string              m_json_begin;
	std::string              m_json_end;
	std::vector<std::string> m_json_filters;
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
};

template <typename T>
const std::string socket_data_handler<T>::HTTP_VERSION_10 = "1.0";
template <typename T>
const std::string socket_data_handler<T>::HTTP_VERSION_11 = "1.1";
template <typename T>
typename socket_data_handler<T>::dns_list_t socket_data_handler<T>::m_pending_dns_reqs;

#endif // HAS_CAPTURE
