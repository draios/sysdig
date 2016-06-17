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
	static const std::string SPECIAL_CHARS;
	static const std::string AMBIGUOUS_CHARS;

	uri() = delete;

	uri(std::string str);

	const std::string& get_scheme() const;
	const std::string& get_user() const;
	const std::string& get_password() const;
	const std::string& get_host() const;
	const std::string& get_path() const;
	const std::string& get_query() const;
	int get_port() const;

	bool is(const std::string& proto);
	bool is_file() const;
	bool is_secure() const;
	std::string get_credentials() const;

	std::string to_string(bool show_creds = true) const;

	// URI-encodes the given string by escaping reserved, ambiguous and non-ASCII
	// characters. Returns the encoded string with uppercase hex letters (eg. %5B, not %5b).
	static std::string encode(const std::string& str, const std::string& reserved = "");

	// URI-decodes the given string by replacing percent-encoded
	// characters with the actual character. Returns the decoded string.
	//
	// When plus_as_space is true, non-encoded plus signs in the query are decoded as spaces.
	// (http://www.w3.org/TR/html401/interact/forms.html#h-17.13.4.1)
	static std::string decode(const std::string& str, bool plus_as_space = false);

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

inline std::string uri::get_credentials() const
{
	std::string creds;
	if(!m_user.empty())
	{
		creds.append(m_user).append(1, ':').append(m_password);
	}
	return creds;
}
