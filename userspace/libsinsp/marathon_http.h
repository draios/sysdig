//
// marathon_http.h
//

#pragma once

#ifdef HAS_CAPTURE

#include "curl/curl.h"
#include "uri.h"
#include "mesos_http.h"
#include <memory>

class marathon_http : public mesos_http
{
public:
	typedef std::shared_ptr<marathon_http> ptr_t;

	marathon_http(mesos& m, const uri& url, bool framework_info = false);

	~marathon_http();

	int get_watch_socket(long timeout_ms);

	bool refresh_data();

	const std::string& get_id() const;
	const std::string& get_name() const;
	const std::string& get_version() const;

	std::string get_groups(const std::string& group_id);

private:
	bool on_data();
	void on_error(const std::string& err, bool disconnect);
	int wait(curl_socket_t sockfd, int for_recv, long timeout_ms);

	curl_socket_t m_watch_socket;
	std::string   m_data;
	std::string   m_id;
	std::string   m_name;
	std::string   m_version;
};

inline const std::string& marathon_http::get_id() const
{
	return m_id;
}

inline const std::string& marathon_http::get_name() const
{
	return m_name;
}

inline const std::string& marathon_http::get_version() const
{
	return m_version;
}

#endif // HAS_CAPTURE
