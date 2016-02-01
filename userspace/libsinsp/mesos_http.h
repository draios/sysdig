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
	typedef void (mesos::*callback_func_t)(std::string&&, const std::string&);

	mesos_http(mesos& m, const uri& url);

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

protected:
	CURL* get_sync_curl();
	CURL* get_select_curl();
	mesos& get_mesos();
	CURLcode get_data(const std::string& url, std::ostream& os);
	void check_error(CURLcode res);
	void cleanup();
	void cleanup(CURL*);
	int wait(int for_recv);

	callback_func_t get_parse_func();
	static std::string make_request(uri url, curl_version_info_data* m_curl_version = 0);
	bool try_parse(const std::string& json);

private:
	void send_request();
	static size_t write_data(void *ptr, size_t size, size_t nmemb, void *cb);

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

	friend class mesos;

	typedef std::vector<std::string::size_type> pos_vec_t;

	void add_data_chunk(std::istringstream&& chunk_str);
	void extract_data(const std::string& data);
	void handle_data();

	// probably belongs to utils
	template<typename charT>
	struct my_equal
	{
		my_equal( const std::locale& loc ) : m_loc(loc) {}
		bool operator()(charT ch1, charT ch2)
		{
			return std::toupper(ch1, m_loc) == std::toupper(ch2, m_loc);
		}
	private:
		const std::locale& m_loc;
	};

	// find substring (case insensitive)
	template<typename T>
	int ci_find_substr(const T& str1, const T& str2, const std::locale& loc = std::locale())
	{
		typename T::const_iterator it = std::search( str1.begin(), str1.end(),
			str2.begin(), str2.end(), my_equal<typename T::value_type>(loc) );
		if(it != str1.end()) { return it - str1.begin(); }
		return -1; // not found
	}
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

inline bool mesos_http::try_parse(const std::string& json)
{
	Json::Value root;
	return Json::Reader().parse(json, root, true);
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

#endif // HAS_CAPTURE
