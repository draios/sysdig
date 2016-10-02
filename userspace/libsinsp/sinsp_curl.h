//
// sinsp_curl.h
//
// Curl utility
//

#if defined(__linux__)

#pragma once

#include "sinsp.h"
#include "sinsp_int.h"
#include "sinsp_auth.h"
#include "uri.h"
#include "curl/curl.h"
#include <string>
#include <memory>

class sinsp_curl
{
public:
	typedef sinsp_ssl ssl;
	typedef sinsp_bearer_token bearer_token;

	static const long DEFAULT_TIMEOUT_MS = 5000L;

	sinsp_curl(const uri& url, long timeout_ms = DEFAULT_TIMEOUT_MS, bool debug = false);
	sinsp_curl(const uri& url, const std::string& bearer_token_file, long timeout_ms = DEFAULT_TIMEOUT_MS, bool debug = false);
	sinsp_curl(const uri& url,
		const std::string& cert, const std::string& key, const std::string& key_passphrase = "",
		const std::string& ca_cert = "", bool verify_peer = false, const std::string& cert_type = "PEM",
		const std::string& bearer_token_file = "",
		long timeout_ms = DEFAULT_TIMEOUT_MS,
		bool debug = false);
	sinsp_curl(const uri& url, ssl::ptr_t p_ssl = 0, bearer_token::ptr_t p_bt = 0,
				long timeout_ms = DEFAULT_TIMEOUT_MS, bool debug = false);

	~sinsp_curl();

	bool get_data(std::ostream& os);
	std::string get_data(bool do_log = true);

	void set_timeout(long seconds);
	long get_timeout() const;

	void set_url(const std::string& url);
	std::string get_url(bool show_creds = true) const;

	bool is_secure() const;
	ssl::ptr_t get_ssl();
	static void init_ssl(CURL* curl, ssl::ptr_t ssl_data);
	bearer_token::ptr_t get_bt();
	static void init_bt(CURL* curl, bearer_token::ptr_t bt);

	static void enable_debug(CURL* curl, bool enable = true);
	static bool check_error(unsigned ret, bool exc = true);
	static size_t header_callback(char *buffer, size_t size, size_t nitems, void *userdata);
	static bool is_redirect(long http_code);
	static bool handle_redirect(uri& url, std::string&& loc, std::ostream& os);
	static size_t write_data(void *ptr, size_t size, size_t nmemb, void *cb);

private:
	struct data
	{
		char trace_ascii; // 1 or 0
	};
	static data m_config;
	static void dump(const char *text, unsigned char *ptr, size_t size, char nohex);
	static int trace(CURL *handle, curl_infotype type, char *data, size_t size, void *userp);

	void init();

	CURL*               m_curl;
	uri                 m_uri;
	long                m_timeout_ms;
	ssl::ptr_t          m_ssl;
	bearer_token::ptr_t m_bt;
	bool                m_debug;
	char                m_redirect[CURL_MAX_HTTP_HEADER] = {0};
};

inline void sinsp_curl::set_timeout(long milliseconds)
{
	m_timeout_ms = milliseconds;
}

inline long sinsp_curl::get_timeout() const
{
	return m_timeout_ms;
}

inline void sinsp_curl::set_url(const std::string& url)
{
	m_uri = url;
}

inline std::string sinsp_curl::get_url(bool show_creds) const
{
	return m_uri.to_string(show_creds);
}

inline bool sinsp_curl::is_secure() const
{
	return m_uri.is_secure();
}

inline sinsp_curl::ssl::ptr_t sinsp_curl::get_ssl()
{
	return m_ssl;
}

inline sinsp_curl::bearer_token::ptr_t sinsp_curl::get_bt()
{
	return m_bt;
}

#endif // __linux__
