//
// k8s_api_handler.cpp
//

#ifdef HAS_CAPTURE

#include "k8s_api_handler.h"
#include "sinsp.h"
#include "sinsp_int.h"

// filters normalize state and event JSONs, so they can be processed generically:
// event is turned into a single-entry array, state is turned into an array of ADDED events

k8s_api_handler::k8s_api_handler(collector_ptr_t collector,
	const std::string& url,
	const std::string& path,
	const std::string& filter,
	const std::string& http_version
#ifdef HAS_CAPTURE
	,ssl_ptr_t ssl
	,bt_ptr_t bt
	,bool blocking_socket
#endif // HAS_CAPTURE
):
		k8s_handler("k8s_api_handler", false,
#ifdef HAS_CAPTURE
					url, path, filter, ".", collector, http_version, 1000L, ssl, bt,
#endif // HAS_CAPTURE
					false, true, std::make_shared<k8s_dummy_handler>(), blocking_socket, nullptr)
{
}

k8s_api_handler::~k8s_api_handler()
{
}

bool k8s_api_handler::handle_component(const Json::Value& json, const msg_data* data)
{
	m_error = false;
	if(!json.isNull())
	{
		if(json.isArray())
		{
			for(const auto& version : json)
			{
				if(version.isConvertibleTo(Json::stringValue))
				{
					m_extensions.push_back(version.asString());
				}
				else
				{
					g_logger.log("K8s API handler error: could not extract versions from JSON.",
						 sinsp_logger::SEV_ERROR);
					m_error = true;
					return false;
				}
			}
		}
		else if(json.isConvertibleTo(Json::stringValue))
		{
			m_extensions.push_back(json.asString());
		}
		else
		{
			g_logger.log("K8s API handler error: could not extract version from JSON.",
						 sinsp_logger::SEV_ERROR);
			m_error = true;
			return false;
		}
		m_data_received = true;
	}
	else
	{
		g_logger.log("K8s API handler error: json is null.", sinsp_logger::SEV_ERROR);
		m_error = true;
		return false;
	}
	return true;
}

void k8s_api_handler::handle_json(Json::Value&& root)
{
	if(g_logger.get_severity() >= sinsp_logger::SEV_TRACE)
	{
		g_logger.log("K8S API handler: \n" + json_as_string(root), sinsp_logger::SEV_TRACE);
	}

	handle_component(root);
}

bool k8s_api_handler::has(const std::string& version) const
{
	for(const auto& ver : m_extensions)
	{
		if(ver == version)
		{
			return true;
		}
	}
	return false;
}
 
 #endif // HAS_CAPTURE
 