/*
Copyright (C) 2013-2014 Draios inc.

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

#include "http_reason.h"

const std::map<int, std::string> http_reason::m_http_reason =
	  { { 100, "Continue" },
		{ 101, "Switching Protocols" },
		{ 102, "Processing" },
		{ 200, "OK" },
		{ 201, "Created" },
		{ 202, "Accepted" },
		{ 203, "Non-Authoritative Information" },
		{ 204, "No Content" },
		{ 205, "Reset Content" },
		{ 206, "Partial Content" },
		{ 207, "Multi Status" },
		{ 208, "Already Reported" },
		{ 226, "IM Used" },
		{ 300, "Multiple Choices" },
		{ 301, "Moved Permanently" },
		{ 302, "Found" },
		{ 303, "See Other" },
		{ 304, "Not Modified" },
		{ 305, "Use Proxy" },
		{ 307, "Temporary Redirect" },
		{ 308, "Permanent Redirect" },
		{ 400, "Bad Request" },
		{ 401, "Unauthorized" },
		{ 402, "Payment Required" },
		{ 403, "Forbidden" },
		{ 404, "Not Found" },
		{ 405, "Method Not Allowed" },
		{ 406, "Not Acceptable" },
		{ 407, "Proxy Authentication Required" },
		{ 408, "Request Time-out" },
		{ 409, "Conflict" },
		{ 410, "Gone" },
		{ 411, "Length Required" },
		{ 412, "Precondition Failed" },
		{ 413, "Request Entity Too Large" },
		{ 414, "Request-URI Too Long" },
		{ 415, "Unsupported Media Type" },
		{ 416, "Requested Range Not Satisfiable" },
		{ 417, "Expectation Failed" },
		{ 418, "I'm a Teapot" },
		{ 420, "Enhance Your Calm" },
		{ 421, "Misdirected Request" },
		{ 422, "Unprocessable Entity" },
		{ 423, "Locked" },
		{ 424, "Failed Dependency" },
		{ 426, "Upgrade Required" },
		{ 428, "Precondition Required" },
		{ 429, "Too Many Requests" },
		{ 431, "Request Header Fields Too Large" },
		{ 451, "Unavailable For Legal Reasons" },
		{ 500, "Internal Server Error" },
		{ 501, "Not Implemented" },
		{ 502, "Bad Gateway" },
		{ 503, "Service Unavailable" },
		{ 504, "Gateway Time-Out" },
		{ 505, "HTTP Version Not Supported" },
		{ 506, "Variant Also Negotiates" },
		{ 507, "Insufficient Storage" },
		{ 508, "Loop Detected" },
		{ 510, "Not Extended" },
		{ 511, "Network Authentication Required" } };

std::string http_reason::get(int status)
{
	auto it = m_http_reason.find(status);
	if(it != m_http_reason.end())
	{
		return it->second;
	}
	return "";
}
