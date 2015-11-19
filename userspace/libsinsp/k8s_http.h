//
// k8s_http.h
//

#pragma once

#include "curl/curl.h"
#include <iosfwd>
#include <map>
#include <string>

class k8s;

class k8s_http
{
public:
	k8s_http(k8s& k8s,
		const std::string& component,
		const std::string& host_and_port = "localhost:80",
		const std::string& protocol = "http",
		const std::string& credentials = "",
		const std::string& api = "/api/v1");

	~k8s_http();

	bool get_all_data(std::ostream& os);

	int get_watch_socket(long timeout_ms);

	bool is_connected() const;

	bool on_data();

	void on_error(const std::string& err, bool disconnect);

private:
	bool init();
	void cleanup();

	int wait(curl_socket_t sockfd, int for_recv, long timeout_ms);
	static size_t write_data(void *ptr, size_t size, size_t nmemb, void *cb);
	static void check_error(CURLcode res);

	CURL*         m_curl;
	k8s&          m_k8s;
	std::string   m_protocol;
	std::string   m_host_and_port;
	std::string   m_api;
	std::string   m_component;
	std::string   m_credentials;
	std::string   m_url;
	curl_socket_t m_watch_socket;
	bool          m_data_ready;
};

inline bool k8s_http::is_connected() const
{
	return m_curl != 0;
}

