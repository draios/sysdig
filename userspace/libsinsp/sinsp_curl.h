//
// sinsp_curl.h
//
// Curl utility
//

#if defined(__linux__)

#pragma once

#include "sinsp.h"
#include "sinsp_int.h"
#include "uri.h"
#include "curl/curl.h"
#include <string>
#include <memory>

class sinsp_curl
{
public:
	class ssl
	{
	public:
		typedef std::shared_ptr<ssl> ptr_t;

		ssl(const std::string& cert, const std::string& key, const std::string& key_passphrase = "",
			const std::string& ca_cert = "", bool verify_peer = false, const std::string& cert_type = "PEM");
		~ssl();

		const std::string& cert_type() const;
		const std::string& cert() const;
		const std::string& key() const;
		const std::string& key_passphrase() const;
		const std::string& ca_cert() const;
		bool verify_peer() const;

	private:
		static std::string memorize_file(const std::string& disk_file);
		static void unmemorize_file(const std::string& mem_file);

		std::string m_cert_type;
		std::string m_cert;
		std::string m_key;
		std::string m_key_passphrase;
		std::string m_ca_cert;
		bool        m_verify_peer = false;
	};

	class bearer_token
	{
	public:
		typedef std::shared_ptr<bearer_token> ptr_t;

		bearer_token(const std::string& bearer_token_file = "");
		~bearer_token();

		const std::string& get_token() const;
		struct curl_slist* bt_auth_header();

	private:
		static std::string stringize_file(const std::string& disk_file);

		std::string m_bearer_token;
		struct curl_slist* m_bt_auth_header;
	};

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
	std::string get_data();

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

private:
	struct data
	{
		char trace_ascii; // 1 or 0
	};
	static data m_config;
	static void dump(const char *text, unsigned char *ptr, size_t size, char nohex);
	static int trace(CURL *handle, curl_infotype type, char *data, size_t size, void *userp);

	void init();
	static size_t write_data(void *ptr, size_t size, size_t nmemb, void *cb);

	CURL*               m_curl;
	uri                 m_uri;
	long                m_timeout_ms;
	ssl::ptr_t          m_ssl;
	bearer_token::ptr_t m_bt;
	bool                m_debug;
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


//
// sinsp_curl::bearer_token
//

inline sinsp_curl::bearer_token::ptr_t sinsp_curl::get_bt()
{
	return m_bt;
}

inline const std::string& sinsp_curl::bearer_token::get_token() const
{
	return m_bearer_token;
}

inline struct curl_slist* sinsp_curl::bearer_token::bt_auth_header()
{
	return m_bt_auth_header;
}


//
// sinsp_curl::ssl
//

inline const std::string& sinsp_curl::ssl::cert_type() const
{
	return m_cert_type;
}

inline const std::string& sinsp_curl::ssl::cert() const
{
	return m_cert;
}

inline const std::string& sinsp_curl::ssl::key() const
{
	return m_key;
}

inline const std::string& sinsp_curl::ssl::key_passphrase() const
{
	return m_key_passphrase;
}

inline const std::string& sinsp_curl::ssl::ca_cert() const
{
	return m_ca_cert;
}

inline bool sinsp_curl::ssl::verify_peer() const
{
	return m_verify_peer;
}

#endif // __linux__
