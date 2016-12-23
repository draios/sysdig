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

class mesos_auth
{
public:
	mesos_auth(const uri::credentials_t& dcos_enterprise_credentials = uri::credentials_t());
	virtual ~mesos_auth();

	void authenticate();
	virtual void refresh_token();

	// Return the current token. It's up to the caller to know
	// when the token has been refreshed, making the returned
	// token obsolete.
	string get_token();

protected:
	string             m_token;

private:
	const uri::credentials_t m_dcos_enterprise_credentials;
};

