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
#include "sinsp_curl.h"

template <typename T>
class socket_data_handler
{
public:
	typedef std::shared_ptr<socket_data_handler> ptr_t;
	typedef std::shared_ptr<Json::Value>         json_ptr_t;
	typedef sinsp_curl::ssl::ptr_t               ssl_ptr_t;
	typedef sinsp_curl::bearer_token::ptr_t      bt_ptr_t;
	typedef void (T::*json_callback_func_t)(json_ptr_t, const std::string&);

	static const std::string HTTP_VERSION_10;
	static const std::string HTTP_VERSION_11;

	socket_data_handler(T& obj,
						const std::string& id,
						const std::string& url,
						const std::string& path = "",
						const std::string& http_version = HTTP_VERSION_11,
						int timeout_ms = 5000L,
						ssl_ptr_t ssl = 0,
						bt_ptr_t bt = 0):
		m_obj(obj),
		m_id(id),
		m_url(url),
		m_path(path.empty() ? m_url.get_path() : path),
		m_connected(true),
		m_watch_socket(-1),
		m_ssl(ssl),
		m_bt(bt),
		m_timeout_ms(timeout_ms),
		m_json_callback(0),
		m_request(make_request(m_url, http_version)),
		m_http_version(http_version),
		m_json_begin("\r\n{"),
		m_json_end(m_http_version == HTTP_VERSION_10 ? "}\r\n" : "}\r\n0"),
		m_ssl_context(0),
		m_ssl_connection(0),
		m_content_length(std::string::npos)
	{
		g_logger.log(std::string("Creating Socket handler object for (" + id + ") [" + url + ']'), sinsp_logger::SEV_DEBUG);
	}

	virtual ~socket_data_handler()
	{
		cleanup();
		SSL_CTX_free(m_ssl_context);
	}

	virtual int get_socket(long timeout_ms = -1)
	{
		if(timeout_ms != -1)
		{
			m_timeout_ms = timeout_ms;
		}

		if(m_watch_socket < 0 || !m_connected)
		{
			connect_socket();
		}

		m_connected = true;
		return m_watch_socket;
	}

	virtual bool is_connected() const
	{
		return m_connected;
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

		if(m_watch_socket < 0)
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
					iolen = send(m_watch_socket, m_request.c_str(), m_request.size(), 0);
				}
				if(iolen == req.size()) { break; }
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
			g_logger.log("Socket handler (" + m_id + ") connection [" + m_url.to_string() + "] error : " + err, sinsp_logger::SEV_ERROR);
			if(m_url.is_secure())
			{
				std::string ssl_err = ssl_errors();
				if(!ssl_err.empty())
				{
					g_logger.log(ssl_err, sinsp_logger::SEV_ERROR);
				}
			}
			throw sinsp_exception("Socket handler (" + m_id + ") send error.");
		}

		connection_closed:
		{
			throw sinsp_exception("Socket handler (" + m_id + ") connection [" + m_url.to_string() + "] closed.");
		}
	}

	bool on_data()
	{
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
				ioret = ioctl(m_watch_socket, FIONREAD, &count);
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
						iolen = recv(m_watch_socket, &buf[0], count, 0);
					}
					if(iolen > 0)
					{
						data.append(&buf[0], iolen <= buf.size() ? iolen : buf.size());
					}
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
			g_logger.log(std::string("Socket handler data receive error [" + m_url.to_string() + "]: ").append(ex.what()), sinsp_logger::SEV_ERROR);
			return false;
		}
		return true;

	connection_error:
	{
		std::string err = strerror(errno);
		g_logger.log("Socket handler (" + m_id + ") connection [" + m_url.to_string() + "] error : " + err, sinsp_logger::SEV_ERROR);
		if(m_url.is_secure())
		{
			std::string ssl_err = ssl_errors();
			if(!ssl_err.empty())
			{
				g_logger.log("Socket handler (" + m_id + ") SSL error : " + ssl_err, sinsp_logger::SEV_ERROR);
			}
		}
		return false;
	}

	connection_closed:
		g_logger.log("Socket handler (" + m_id + ") connection [" + m_url.to_string() + "] closed.", sinsp_logger::SEV_ERROR);
		m_connected = false;
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

	void set_json_filter(const std::string& filter)
	{
		m_json_filter = filter;
	}

	static json_ptr_t try_parse(json_query& jq, std::string&& json, const std::string& filter,
								const std::string& id, const std::string& url)
	{
		if(!filter.empty())
		{
			if(jq.process(json, filter))
			{
				json = jq.result();
			}
			else
			{
				g_logger.log("Socket handler (" + id + "), [" + url + "] parsing error; " + json + ", jq filter: <" + filter + '>',
							 sinsp_logger::SEV_ERROR);
				return nullptr;
			}
		}
		json_ptr_t root(new Json::Value());
		try
		{
			if(Json::Reader().parse(json, *root))
			{
				return root;
			}
		}
		catch(...) { }
		g_logger.log("Socket handler (" + id + "), [" + url + "] parsing error; JSON: <" + json + ">, jq filter: <" + filter + '>',
					 sinsp_logger::SEV_ERROR);
		return nullptr;
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
						g_logger.log("Socket handler (" + m_id + "): Invalid JSON data detected (chunked transfer).", sinsp_logger::SEV_ERROR);
						(m_obj.*m_json_callback)(nullptr, m_id);
					}
					else
					{
						(m_obj.*m_json_callback)(try_parse(m_jq, std::move(json), m_json_filter, m_id, m_url.to_string(false)), m_id);
					}
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
		if(data.empty()) { return; }
		if(!detect_chunked_transfer(data))
		{
			g_logger.log("Socket handler (" + m_id + "): An error occurred while detecting chunked transfer.", sinsp_logger::SEV_ERROR);
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
		FD_SET(m_watch_socket, &errfd);
		if(for_recv)
		{
			FD_SET(m_watch_socket, &infd);
		}
		else
		{
			FD_SET(m_watch_socket, &outfd);
		}

		return select(m_watch_socket + 1, &infd, &outfd, &errfd, &tv);
	}

	static int ssl_verify_callback(int preverify_ok, X509_STORE_CTX* ctx)
	{
		SSL* ssl = (SSL*)X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
		if(ssl)
		{
			char      buf[256] = {0};
			X509*     err_cert = X509_STORE_CTX_get_current_cert(ctx);
			X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);

			if(preverify_ok && SSL_get_verify_result(ssl) == X509_V_OK)
			{
				g_logger.log("Socket handler SSL CA verified: " + std::string(buf), sinsp_logger::SEV_INFO);
				return 1;
			}
			else
			{
				int err = X509_STORE_CTX_get_error(ctx);
				int depth = X509_STORE_CTX_get_error_depth(ctx);
				g_logger.log("SSL CA verify error:num=" + std::to_string(err) +
							 ':' + X509_verify_cert_error_string(err) +
							 ":depth=" + std::to_string(depth) +
							 ':' + std::string(buf), sinsp_logger::SEV_ERROR);
				return 0;
			}
		}
		return 0;
	}

	static int ssl_verify_callback_ignore(int, X509_STORE_CTX*)
	{
		g_logger.log("Socket handler SSL CA verification disabled.", sinsp_logger::SEV_INFO);
		return 1;
	}

	static int ssl_key_password_cb(char *buf, int size, int, void* pass)
	{
		if(pass)
		{
			std::memset(buf, 0, size);
			std::size_t pass_len = strlen((char*)pass);
			if(size < (pass_len + 1)) { return 0; }
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
					os << "Socket handler (" + m_id + ") SSL errors:\n";
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
			const SSL_METHOD* method = TLSv1_2_client_method(); // SSLv23_method();
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
				}
				else
				{
					SSL_CTX_set_verify(m_ssl_context, SSL_VERIFY_NONE, ssl_verify_callback_ignore);
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
						if(!SSL_CTX_check_private_key(m_ssl_context))
						{
							throw sinsp_exception("Socket handler (" + m_id + "): "
											  "SSL private key (" + key + ") does not match public certificate (" + cert + ").\n" +
											  ssl_errors());
						}
					}
					else
					{
						throw sinsp_exception("Socket handler (" + m_id + "): "
											  "Invalid SSL configuration: public certificate specified without private key.");
					}
				}
			}
		}
	}

	void init_ssl_socket()
	{
		if(m_watch_socket != -1)
		{
			if(m_url.is_secure())
			{
				if(!m_ssl_context) { init_ssl_context(); }
				if(m_ssl_context)
				{
					m_ssl_connection = SSL_new(m_ssl_context);
					if(m_ssl_connection)
					{
						if(0 == SSL_set_fd(m_ssl_connection, m_watch_socket))
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
		if(m_watch_socket < 0)
		{
			if(m_url.is_file())
			{
				m_watch_socket = socket(PF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
			}
			else
			{
				m_watch_socket = socket(PF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
			}
			if(m_watch_socket < 0)
			{
				throw sinsp_exception("Socket handler " + m_id + " (" + m_url.to_string(false) + ") "
									  "error obtaining socket: " + strerror(errno));
			}
		}
	}

	void connect_socket()
	{
		struct sockaddr_un file_addr = {0};
		struct sockaddr_in serv_addr = {0};
		struct sockaddr*   sa = 0;
		socklen_t          sa_len = 0;
		if(m_url.is_file())
		{
			if(m_url.get_path().length() > sizeof(file_addr.sun_path) - 1)
			{
				throw sinsp_exception("Invalid address (too long): [" + m_url.get_path() + ']');
			}

			file_addr.sun_family = AF_UNIX;
			strncpy(file_addr.sun_path, m_url.get_path().c_str(), m_url.get_path().length());
			file_addr.sun_path[sizeof(file_addr.sun_path) - 1]= '\0';
			sa = (sockaddr*)&file_addr;
			sa_len = sizeof(struct sockaddr_un);
		}
		else if(m_url.is("https") || m_url.is("http"))
		{
			if(!inet_aton(m_url.get_host().c_str(), &serv_addr.sin_addr))
			{
				// not IP address, try hostname
				struct addrinfo *result = 0;
				//TODO: getaddrinfo blocks, use getaddrinfo_a ?
				if (0 == getaddrinfo(m_url.get_host().c_str(), NULL, NULL, &result))
				{
					create_socket();
					for (struct addrinfo* ai = result; ai; ai = ai->ai_next)
					{
						if (ai->ai_addrlen && ai->ai_addr && ai->ai_addr->sa_family == AF_INET)
						{
							struct sockaddr_in* saddr = (struct sockaddr_in*)ai->ai_addr;
							if(saddr->sin_addr.s_addr)
							{
								serv_addr.sin_addr.s_addr = saddr->sin_addr.s_addr;
								break;
							}
						}
					}
					if(!serv_addr.sin_addr.s_addr)
					{
						throw sinsp_exception("Socket handler (" + m_id + "): " + m_url.get_host() + " address not found.");
					}
				}
				else
				{
					freeaddrinfo(result);
					throw sinsp_exception("Socket handler error: can not resolve host " + m_url.get_host() + ", error: " + strerror(errno));
				}
				freeaddrinfo(result);
			}
			serv_addr.sin_family = AF_INET;
			serv_addr.sin_port = htons(m_url.get_port());
			sa = (sockaddr*)&serv_addr;
			sa_len = sizeof(struct sockaddr_in);
		}
		if(sa && sa_len)
		{
			create_socket();
			std::string addr_str = (m_url.is_file() ? m_url.get_path().c_str() : inet_ntoa(serv_addr.sin_addr));
			g_logger.log("Socket handler (" + m_id + ") connecting to " + addr_str, sinsp_logger::SEV_INFO);
			connect(m_watch_socket, sa, sa_len);
			if(m_url.is_secure())
			{
				init_ssl_socket();
				if(m_ssl_connection)
				{
					SSL_connect(m_ssl_connection);
				}
				else
				{
					throw sinsp_exception("Socket handler (" + m_id + "): " + addr_str +
									  " SSL connection is null (" + strerror(errno) + ')');
				}
			}
			time_t then; time(&then);
			while(wait(false, 10L) == -1)
			{
				g_logger.log("Socket handler (" + m_id + "): waiting for connection to " + addr_str, sinsp_logger::SEV_DEBUG);
				time_t now; time(&now);
				if(difftime(now, then) > m_timeout_ms * 1000)
				{
					throw sinsp_exception("Socket handler (" + m_id + "): " + addr_str +
									  " timed out waiting for connection.");
				}
			}
			g_logger.log("Socket handler (" + m_id + "): Connected: socket=" + std::to_string(m_watch_socket) +
						 ", collecting data from " + m_url.to_string(false), sinsp_logger::SEV_INFO);

			if(SSL_get_peer_certificate(m_ssl_connection))
			{
				if(SSL_get_verify_result(m_ssl_connection) != X509_V_OK)
				{
					throw sinsp_exception("Socket handler (" + m_id + "): " + addr_str +
										  " server certificate verification failed.");
				}
			}
		}
		else
		{
			throw sinsp_exception("Socket handler (" + m_id + "): " + m_url.get_scheme() + " protocol not supported.");
		}
	}

	void cleanup()
	{
		if(m_watch_socket)
		{
			close(m_watch_socket);
			m_watch_socket = -1;
			SSL_free(m_ssl_connection);
			m_ssl_connection = 0;
		}
	}

	T&                     m_obj;
	std::string            m_id;
	uri                    m_url;
	std::string            m_path;
	bool                   m_connected;
	int                    m_watch_socket;
	ssl_ptr_t              m_ssl;
	bt_ptr_t               m_bt;
	long                   m_timeout_ms;
	json_callback_func_t   m_json_callback;
	std::string            m_data_buf;
	std::string            m_request;
	std::string            m_http_version;
	std::string            m_json_begin;
	std::string            m_json_end;
	std::string            m_json_filter;
	json_query             m_jq;
	SSL_CTX*               m_ssl_context;
	SSL*                   m_ssl_connection;
	password_vec_t         m_ssl_key_pass;
	std::string::size_type m_content_length;
};

template <typename T>
const std::string socket_data_handler<T>::HTTP_VERSION_10 = "1.0";
template <typename T>
const std::string socket_data_handler<T>::HTTP_VERSION_11 = "1.1";

#endif // HAS_CAPTURE
