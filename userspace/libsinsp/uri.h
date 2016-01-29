//
// uri.h
//
// URI utilities
//

#pragma once

#include <string>

class uri
{
public:
	uri() = delete;
	
	uri(std::string str);

	const std::string& get_scheme() const;
	void set_scheme(const std::string&  scheme);

	const std::string& get_user() const;
	void set_user(const std::string& user);

	const std::string& get_password() const;
	void set_password(const std::string& password);

	const std::string& get_host() const;
	void set_host(const std::string& host);

	const std::string& get_path() const;
	void set_path (const std::string& path);

	const std::string& get_query() const;
	void set_query(const std::string& query);

	int get_port() const;
	void set_port(int port);

	bool is_secure() const;
	std::string get_credentials() const;

	std::string to_string() const;

private:
	std::string tail_chunk(std::string& subject, std::string delimiter, bool keep_delim = false);
	std::string head_chunk(std::string& subject, std::string delimiter);

	int extract_port(std::string& hostport);
	std::string extract_path(std::string& str);
	std::string extract_protocol(std::string& str);
	std::string extract_query(std::string& str);
	std::string extract_password(std::string& userpass);
	std::string extract_auth(std::string& str);
	
	std::string m_scheme, m_user, m_password, m_host, m_path, m_query;
    int m_port;
};

inline const std::string& uri::get_scheme() const
{
	return m_scheme;
}

inline void uri::set_scheme(const std::string&  scheme)
{
	m_scheme = scheme;
}

inline const std::string& uri::get_user() const
{
	return m_user;
}

inline void uri::set_user(const std::string&  user)
{
	m_user = user;
}

inline const std::string& uri::get_password() const
{
	return m_password;
}

inline void uri::set_password(const std::string&  password)
{
	m_password = password;
}

inline const std::string& uri::get_host() const
{
	return m_host;
}

inline void uri::set_host(const std::string&  host)
{
	m_host = host;
}

inline const std::string& uri::get_path() const
{
	return m_path;
}

inline void uri::set_path(const std::string&  path)
{
	m_path = path;
}

inline const std::string& uri::get_query() const
{
	return m_query;
}

inline void uri::set_query(const std::string&  query)
{
	m_query = query;
}

inline int uri::get_port() const
{
	return m_port;
}

inline void uri::set_port(int port)
{
	m_port = port;
}

inline std::string uri::extract_path(std::string& str)
{
	return tail_chunk(str, "/", true);
}

inline std::string uri::extract_protocol(std::string& str)
{
	return head_chunk(str, "://");
}

inline std::string uri::extract_query(std::string& str)
{
	return tail_chunk(str, "?");
}

inline std::string uri::extract_password(std::string &userpass)
{
	return tail_chunk(userpass, ":");
}

inline std::string uri::extract_auth(std::string& str)
{
	return head_chunk(str, "@"); 
}

inline bool uri::is_secure() const
{
	return "https" == m_scheme;
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
