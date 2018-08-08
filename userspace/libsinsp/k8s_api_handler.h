//
// k8s_api_handler.h
//

#ifdef HAS_CAPTURE

#pragma once

#include "nlohmann/json.hpp"
#include "k8s_handler.h"

class k8s_api_handler : public k8s_handler
{
public:
	typedef std::vector<std::string> api_list_t;

	k8s_api_handler(collector_ptr_t collector,
		const std::string& url,
		const std::string& path,
		const std::string& filter,
		const std::string& http_version = "1.1",
		ssl_ptr_t ssl = 0,
		bt_ptr_t bt = 0,
		bool blocking_socket = false);

	~k8s_api_handler();

	bool error() const;
	const api_list_t& extensions() const;
	bool has(const std::string& version) const;

private:
	void handle_json(json&& root);
	bool handle_component(const json& json, const msg_data* data = 0);


	api_list_t m_extensions;
	bool       m_error = false;
};

inline bool k8s_api_handler::error() const
{
	return m_error;
}

inline const k8s_api_handler::api_list_t& k8s_api_handler::extensions() const
{
	return m_extensions;
}

#endif // HAS_CAPTURE
