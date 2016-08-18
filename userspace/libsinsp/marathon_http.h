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

	marathon_http(mesos& m, const uri& url, bool discover_marathon, int timeout_ms = 5000L);

	~marathon_http();

	bool refresh_data();

	std::string get_groups(const std::string& group_id);

private:
	std::string m_data;
};

#endif // HAS_CAPTURE
