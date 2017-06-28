//
// sinsp_auth.h
//
// Authentication/verification utilities
//

#if defined(__linux__)

#pragma once

#include "sinsp.h"
#include "sinsp_int.h"
#include "uri.h"
#include "curl/curl.h"
#include <string>
#include <memory>

class sinsp_ssl
{
public:
	typedef std::shared_ptr<sinsp_ssl> ptr_t;

	sinsp_ssl(const std::string& cert, const std::string& key, const std::string& key_passphrase = "",
		const std::string& ca_cert = "", bool verify_peer = false, const std::string& cert_type = "PEM");
	~sinsp_ssl();

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

class sinsp_bearer_token
{
public:
	typedef std::shared_ptr<sinsp_bearer_token> ptr_t;

	sinsp_bearer_token(const std::string& bearer_token_file, bool curl_support = true);
	~sinsp_bearer_token();

	const std::string& get_token() const;
	struct curl_slist* bt_auth_header();

private:
	static std::string stringize_file(const std::string& disk_file);

	std::string m_bearer_token;
	struct curl_slist* m_bt_auth_header;
};


//
// ssl
//

inline const std::string& sinsp_ssl::cert_type() const
{
	return m_cert_type;
}

inline const std::string& sinsp_ssl::cert() const
{
	return m_cert;
}

inline const std::string& sinsp_ssl::key() const
{
	return m_key;
}

inline const std::string& sinsp_ssl::key_passphrase() const
{
	return m_key_passphrase;
}

inline const std::string& sinsp_ssl::ca_cert() const
{
	return m_ca_cert;
}

inline bool sinsp_ssl::verify_peer() const
{
	return m_verify_peer;
}


//
// bearer_token
//

inline const std::string& sinsp_bearer_token::get_token() const
{
	return m_bearer_token;
}

inline struct curl_slist* sinsp_bearer_token::bt_auth_header()
{
	return m_bt_auth_header;
}

#endif // __linux__
