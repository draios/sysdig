/*
Copyright (C) 2013-2016 Draios inc.

This file is part of sysdig.

sysdig is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.

sysdig is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with sysdig.  If not, see <http://www.gnu.org/licenses/>.
*/

//
// mesos_auth.cpp
//

#include <time.h>

#include "mesos_auth.h"

using namespace std;

mesos_auth::mesos_auth(const uri::credentials_t& dcos_enterprise_credentials,
		       string auth_hostname,
		       int token_refresh_interval)
	: m_dcos_enterprise_credentials(dcos_enterprise_credentials),
	  m_auth_uri(string("https://") + auth_hostname + string("/acs/api/v1/auth/login")),
	  m_token_refresh_interval(token_refresh_interval),
	  m_last_token_refresh_s(0)

{
	if(!m_dcos_enterprise_credentials.first.empty())
	{
		authenticate();
	}
}

mesos_auth::~mesos_auth()
{
}

string mesos_auth::get_token()
{
	refresh_token();
	return m_token;
}

void mesos_auth::authenticate()
{
#ifdef HAS_CAPTURE

	try
	{
		sinsp_curl auth_request(m_auth_uri, "", "");
		Json::FastWriter json_writer;
		Json::Value auth_obj;
		auth_obj["uid"] = m_dcos_enterprise_credentials.first;
		auth_obj["password"] = m_dcos_enterprise_credentials.second;
		auth_request.add_header("Content-Type: application/json");
		auth_request.setopt(CURLOPT_POST, 1);
		auth_request.set_body(json_writer.write(auth_obj));
		//auth_request.enable_debug();
		auto response = auth_request.get_data();

		if(auth_request.get_response_code() == 200)
		{
			Json::Reader json_reader;
			Json::Value response_obj;
			auto parse_ok = json_reader.parse(response, response_obj, false);
			if(parse_ok && response_obj.isMember("token"))
			{
				m_token = response_obj["token"].asString();
				g_logger.format(sinsp_logger::SEV_DEBUG, "Mesos authenticated with token=%s", m_token.c_str());
			}
			else
			{
				throw sinsp_exception(string("Cannot authenticate on Mesos master, response=") + response);
			}
		} else
		{
			throw sinsp_exception(string("Cannot authenticate on Mesos master, response_code=") + to_string(auth_request.get_response_code()));
		}
		time(&m_last_token_refresh_s);
	}
	catch(std::exception& e)
	{
		g_logger.format(sinsp_logger::SEV_ERROR,
				"Could not fetch authentication token via %s: %s",
				m_auth_uri.to_string().c_str(),
				e.what());
	}
#endif // HAS_CAPTURE
}

void mesos_auth::refresh_token()
{
#ifdef HAS_CAPTURE
	if(!m_dcos_enterprise_credentials.first.empty())
	{
		time_t now; time(&now);

		if(difftime(now, m_last_token_refresh_s) > m_token_refresh_interval)
		{
			g_logger.format(sinsp_logger::SEV_DEBUG, "Regenerating Mesos Auth token");
			authenticate();
		}
	}
#endif // HAS_CAPTURE
}

