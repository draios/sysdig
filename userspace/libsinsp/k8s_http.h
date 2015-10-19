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

	int get_watch_socket();

	void on_data();

	void on_error();

private:
	struct my_equal
	{
		bool operator()(char ch1, char ch2)
		{
			return std::toupper(ch1) == std::toupper(ch2);
		}
	};

	int wait(curl_socket_t sockfd, int for_recv, long timeout_ms);
	static size_t write_data(void *ptr, size_t size, size_t nmemb, void *cb);
	static void check_error(CURLcode res);
	// find substring (case insensitive)
	static int ci_find_substr(const std::string& str1, const std::string& str2);

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

