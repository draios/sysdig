//
// uri.h
//
// URI utility
//

#pragma once

#ifdef _WIN32
#pragma warning(disable: 4190)
#endif

#include "uri_parser.h"
#include <string>

// TODO: support fragments
class uri
{
public:
	typedef std::pair<std::string, std::string> credentials_t;

	static const std::string SPECIAL_CHARS;
	static const std::string AMBIGUOUS_CHARS;

	uri() = delete;

	uri(std::string str);

	const std::string& get_scheme() const;
	const std::string& get_user() const;
	const std::string& get_password() const;
	const std::string& get_host() const;
	const std::string& get_path() const;
	void set_path(const std::string& path);
	const std::string& get_query() const;
	int get_port() const;

	bool is(const std::string& proto);
	bool is_file() const;
	bool is_secure() const;
	std::string get_credentials() const;
	credentials_t& get_credentials(credentials_t& creds) const;
	void set_credentials(const credentials_t& cred);

	std::string to_string(bool show_creds = true) const;
	bool is_local() const;

	// URI-encodes the given string by escaping reserved, ambiguous and non-ASCII
	// characters. Returns the encoded string with uppercase hex letters (eg. %5B, not %5b).
	static std::string encode(const std::string& str, const std::string& reserved = "");

	// URI-decodes the given string by replacing percent-encoded
	// characters with the actual character. Returns the decoded string.
	//
	// When plus_as_space is true, non-encoded plus signs in the query are decoded as spaces.
	// (http://www.w3.org/TR/html401/interact/forms.html#h-17.13.4.1)
	static std::string decode(const std::string& str, bool plus_as_space = false);
	static void check(std::string str);

private:
	int get_well_known_port() const;

	std::string m_scheme, m_user, m_password, m_host, m_path, m_query;
	int m_port;
	bool m_has_port = true;
};

inline const std::string& uri::get_scheme() const
{
	return m_scheme;
}

inline const std::string& uri::get_user() const
{
	return m_user;
}

inline const std::string& uri::get_password() const
{
	return m_password;
}

inline const std::string& uri::get_host() const
{
	return m_host;
}

inline const std::string& uri::get_path() const
{
	return m_path;
}

inline const std::string& uri::get_query() const
{
	return m_query;
}

inline int uri::get_port() const
{
	return m_port;
}

inline bool uri::is_file() const
{
	return m_scheme == "file";
}

inline bool uri::is_secure() const
{
	return m_scheme == "https";
}

inline void uri::set_credentials(const credentials_t& cred)
{
	m_user = cred.first;
	m_password = cred.second;
}

inline std::string uri::get_credentials() const
{
	std::string creds;
	if(!m_user.empty())
	{
		creds.append(m_user).append(1, ':').append(m_password);
	}
	return creds;
}

inline uri::credentials_t& uri::get_credentials(credentials_t& creds) const
{
	creds.first = m_user;
	creds.second = m_password;
	return creds;
}

inline bool uri::is_local() const
{
	return m_host == "localhost" || m_host == "127.0.0.1" || m_scheme == "file";
}
