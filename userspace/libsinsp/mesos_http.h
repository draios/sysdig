//
// mesos_http.h
//

#pragma once

#ifdef HAS_CAPTURE

#include "curl/curl.h"
#include "uri.h"
#include "json/json.h"
#include <iostream>
#include <string>
#include <memory>
#include <algorithm>

class mesos;

class mesos_http
{
public:
	typedef std::shared_ptr<mesos_http> ptr_t;
	typedef std::shared_ptr<Json::Value> json_ptr_t;
	typedef void (mesos::*callback_func_t)(json_ptr_t, const std::string&);
	typedef std::vector<std::string> marathon_uri_t;

	mesos_http(mesos& m, const uri& url, bool discover_mesos_lead_master = false, bool discover_marathon = false, int timeout_ms = 5000L);

	virtual ~mesos_http();

	bool get_all_data(callback_func_t);

	virtual int get_socket(long timeout_ms = -1);

	virtual bool is_connected() const;

	virtual bool on_data();

	virtual void on_error(const std::string& err, bool disconnect);

	const uri& get_url() const;
	const std::string& get_request() const;

	std::string make_uri(const std::string& path);

	Json::Value get_task_labels(const std::string& task_id);

	void set_parse_func(callback_func_t parse);

	const std::string& get_framework_id() const;
	void set_framework_id(const std::string& id);
	const std::string& get_framework_name() const;
	void set_framework_name(const std::string& id);
	const std::string& get_framework_version() const;
	void set_framework_version(const std::string& id);

	const marathon_uri_t& get_marathon_uris() const;

protected:
	CURL* get_sync_curl();
	CURL* get_select_curl();
	mesos& get_mesos();
	CURLcode get_data(const std::string& url, std::ostream& os);
	void check_error(CURLcode res);
	void cleanup();
	void cleanup(CURL**);
	int wait(int for_recv);

	callback_func_t get_parse_func();
	static std::string make_request(uri url, curl_version_info_data* m_curl_version = 0);
	static json_ptr_t try_parse(const std::string& json);
	static bool is_framework_active(const Json::Value& framework);
	std::string get_framework_url(const Json::Value& framework);

private:
	void discover_mesos_leader();
	Json::Value get_state_frameworks();
	void discover_framework_uris(const Json::Value& frameworks);

	void send_request();

	CURL*                   m_sync_curl;
	CURL*                   m_select_curl;
	mesos&                  m_mesos;
	std::string             m_protocol;
	uri                     m_url;
	bool                    m_connected;
	curl_socket_t           m_watch_socket;
	long                    m_timeout_ms;
	callback_func_t         m_callback_func;
	std::string             m_data_buf;
	std::string             m_framework_id;
	std::string             m_framework_name;
	std::string             m_framework_version;
	curl_version_info_data* m_curl_version;
	std::string             m_request;
	bool                    m_is_mesos_state;
	marathon_uri_t          m_marathon_uris;
	bool                    m_discover_lead_master;
	bool                    m_discover_marathon;
	//bool                    m_redirect = false;
	std::string::size_type  m_content_length = std::string::npos;
	char                    m_redirect[CURL_MAX_HTTP_HEADER] = {0};

	friend class mesos;

	void extract_data(std::string& data);
	void handle_data();
	bool detect_chunked_transfer(const std::string& data);
	void handle_json(std::string::size_type end_pos, bool chunked);
};

inline bool mesos_http::is_connected() const
{
	return m_connected;
}

inline const uri& mesos_http::get_url() const
{
	return m_url;
}

inline CURL* mesos_http::get_sync_curl()
{
	return m_sync_curl;
}

inline CURL* mesos_http::get_select_curl()
{
	return m_select_curl;
}

inline mesos& mesos_http::get_mesos()
{
	return m_mesos;
}

inline const std::string& mesos_http::get_request() const
{
	return m_request;
}

inline void mesos_http::set_parse_func(callback_func_t parse)
{
	m_callback_func = parse;
}

inline mesos_http::callback_func_t mesos_http::get_parse_func()
{
	return m_callback_func;
}

inline mesos_http::json_ptr_t mesos_http::try_parse(const std::string& json)
{
	json_ptr_t root(new Json::Value());
	try
	{
		if(Json::Reader().parse(json, *root))
		{
			return root;
		}
	}
	catch(...) { }
	return nullptr;
}

inline const std::string& mesos_http::get_framework_id() const
{
	return m_framework_id;
}

inline void mesos_http::set_framework_id(const std::string& id)
{
	m_framework_id = id;
}

inline const std::string& mesos_http::get_framework_name() const
{
	return m_framework_name;
}

inline void mesos_http::set_framework_name(const std::string& name)
{
	m_framework_name = name;
}

inline const std::string& mesos_http::get_framework_version() const
{
	return m_framework_version;
}

inline void mesos_http::set_framework_version(const std::string& version)
{
	m_framework_version = version;
}

inline const mesos_http::marathon_uri_t& mesos_http::get_marathon_uris() const
{
	return m_marathon_uris;
}

#else // !HAS_CAPTURE

#include "json/json.h"

class mesos_http
{
public:
	typedef std::shared_ptr<Json::Value> json_ptr_t;
	static json_ptr_t try_parse(const std::string& json)
	{
		json_ptr_t root(new Json::Value());
		try
		{
			if(Json::Reader().parse(json, *root))
			{
				return root;
			}
		}
		catch(...) { }
		return nullptr;
	}
};

#endif // HAS_CAPTURE
