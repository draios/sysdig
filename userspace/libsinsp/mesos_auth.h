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
// mesos_auth.h
//

#pragma once

#include "json/json.h"
#include "mesos_http.h"
#include "uri.h"

static const uint64_t DCOS_ENTERPRISE_TOKEN_REFRESH_S = 60*60*24; // 1 day

class mesos_auth
{
public:
	mesos_auth(const uri::credentials_t& dcos_enterprise_credentials = uri::credentials_t(),
		   std::string auth_hostname = "localhost",
		   int token_refresh_interval = DCOS_ENTERPRISE_TOKEN_REFRESH_S);
	virtual ~mesos_auth();

	virtual void refresh_token();

	// Return the current token. The token may expire at any time
	// after the token has been returned, so it's best to call
	// get_token periodically, which will internally refresh the
	// token if necessary.
	std::string get_token();

protected:
	std::string             m_token;

private:
	void authenticate();

	const uri::credentials_t m_dcos_enterprise_credentials;
	uri m_auth_uri;
	int m_token_refresh_interval;
	time_t m_last_token_refresh_s;
};

