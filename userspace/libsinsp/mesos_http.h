//
// mesos_http.h
//

#pragma once

#ifdef HAS_CAPTURE

#include "curl/curl.h"
#include "uri.h"
#include "json/json.h"
#include <ostream>
#include <string>
#include <memory>

class mesos;

class mesos_http
{
public:
	typedef std::shared_ptr<mesos_http> ptr_t;
	typedef void (mesos::*parse_func_t)(const std::string&);

	mesos_http(mesos& m, const uri& url);

	virtual ~mesos_http();

	bool get_all_data(parse_func_t);

	virtual int get_socket(long timeout_ms = -1);

	virtual bool is_connected() const;

	virtual bool on_data();

	virtual void on_error(const std::string& err, bool disconnect);

	const uri& get_url() const;
	const std::string& get_request() const;
	void set_request(const std::string& request)
	{
		m_request = request;
	}

	std::string make_uri(const std::string& path);

	Json::Value get_task_labels(const std::string& task_id);

	void set_parse_func(parse_func_t parse);

protected:
	CURL* get_curl();
	mesos& get_mesos();
	CURLcode get_data(const std::string& url, std::ostream& os);
	void check_error(CURLcode res);
	void cleanup();

	int wait(int for_recv);

	parse_func_t get_parse_func();

	bool try_parse(const std::string& json);

private:
	static std::string make_request(uri url);
	void send_request();
	static size_t write_data(void *ptr, size_t size, size_t nmemb, void *cb);

	CURL*         m_curl;
	mesos&        m_mesos;
	std::string   m_protocol;
	uri           m_url;
	bool          m_connected;
	curl_socket_t m_watch_socket;
	long          m_timeout_ms;
	std::string   m_request;
	parse_func_t  m_parse_func;
	std::string   m_data;
};

inline bool mesos_http::is_connected() const
{
	return m_connected;
}

inline const uri& mesos_http::get_url() const
{
	return m_url;
}

inline CURL* mesos_http::get_curl()
{
	return m_curl;
}

inline mesos& mesos_http::get_mesos()
{
	return m_mesos;
}

inline const std::string& mesos_http::get_request() const
{
	return m_request;
}

inline void mesos_http::set_parse_func(parse_func_t parse)
{
	m_parse_func = parse;
}

inline mesos_http::parse_func_t mesos_http::get_parse_func()
{
	return m_parse_func;
}

inline bool mesos_http::try_parse(const std::string& json)
{
	Json::Value root;
	if(Json::Reader().parse(json, root, false))
	{
		return true;
	}
	else
	{
		return false;
	}
}

#endif // HAS_CAPTURE
