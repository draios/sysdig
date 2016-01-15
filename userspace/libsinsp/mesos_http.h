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

class mesos;

class mesos_http
{
public:
	typedef void (mesos::*parse_func_t)(const std::string&);

	mesos_http(mesos& m, const uri& url);

	virtual ~mesos_http();

	bool get_all_data(parse_func_t);

	virtual int get_watch_socket(long timeout_ms);

	virtual bool is_connected() const;

	virtual bool on_data();

	virtual void on_error(const std::string& err, bool disconnect);

	const uri& get_url() const;

	std::string make_uri(const std::string& path);

	Json::Value get_task_labels(const std::string& task_id);

protected:
	CURL* get_curl();
	mesos& get_mesos();
	CURLcode get_data(const std::string& url, std::ostream& os);
	const std::string& get_credentials() const;
	static void check_error(CURLcode res);
	void cleanup();

private:
	static size_t write_data(void *ptr, size_t size, size_t nmemb, void *cb);

	CURL*         m_curl;
	mesos&        m_mesos;
	std::string   m_protocol;
	std::string   m_credentials;
	uri           m_url;
	bool          m_connected;
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

inline const std::string& mesos_http::get_credentials() const
{
	return m_credentials;
}

inline mesos& mesos_http::get_mesos()
{
	return m_mesos;
}

#endif // HAS_CAPTURE
