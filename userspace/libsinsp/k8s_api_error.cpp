//
// k8s_api_error.cpp
//

#include "k8s_api_error.h"

using json = nlohmann::json;

k8s_api_error::k8s_api_error(const msg_data& data, const Json::Value& err):
	m_data(data),
	m_status(get_string(err, "status")),
	m_message(get_string(err, "message")),
	m_reason(get_string(err, "reason")),
	m_details(get_string(err, "details")),
	m_code(get_int(err, "code"))
{
}

k8s_api_error::~k8s_api_error()
{
}

std::string k8s_api_error::get_string(const Json::Value& obj, const std::string& name)
{
	return val.value(name, "");
}

int k8s_api_error::get_int(const Json::Value& obj, const std::string& name)
{
	return val.value(name, 0);
}
