//
// uri.h
//
// URI utilities
//

#include  "uri.h"
#include  <sstream>

uri::uri(std::string str): m_port(0)
{
	m_scheme = extract_protocol(str);
	m_query = extract_query(str);
	m_path = extract_path(str);
	std::string auth = extract_auth(str);
	m_password = extract_password(auth);
	m_user = auth;
	m_port = extract_port(str);
	m_host = str;
}

std::string uri::tail_chunk(std::string &subject, std::string delimiter, bool keep_delim)
{
	auto delimiter_location = subject.find(delimiter);
	auto delimiter_length = delimiter.length();
	std::string output;

	if(delimiter_location != std::string::npos)
	{
		auto start = keep_delim ? delimiter_location : delimiter_location + delimiter_length;
		auto end = subject.length() - start;
		output = subject.substr(start, end);
		subject = subject.substr(0, delimiter_location);
	}
	return output;
}

std::string uri::head_chunk(std::string &subject, std::string delimiter) 
{
	auto delimiter_location = subject.find(delimiter);
	auto delimiter_length = delimiter.length();
	std::string output;
	if(delimiter_location != std::string::npos)
	{
		output = subject.substr(0, delimiter_location);
		subject = subject.substr(delimiter_location + delimiter_length, subject.length() - (delimiter_location + delimiter_length));
	}
	return output;
}

int uri::extract_port(std::string& hostport)
{
	int m_port;
	std::string portstring = tail_chunk(hostport, ":");
	try
	{
		m_port = atoi(portstring.c_str()); 
	}
	catch (std::exception e)
	{
		m_port = 0;
	}
	return m_port;
}

std::string uri::to_string() const
{
	std::ostringstream ostr;
	ostr << m_scheme << "://";
	if(!m_user.empty())
	{
		ostr << m_user << ':' << m_password << '@';
	}
	ostr << m_host;
	if(m_port)
	{
		ostr << ':' << m_port;
	}
	ostr << m_path;
	if(!m_query.empty())
	{
		ostr << '?' << m_query;
	}
	return ostr.str();
}
