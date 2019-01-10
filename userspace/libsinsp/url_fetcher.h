/*
Copyright (C) 2018 Sysdig, Inc.

This file is part of sysdig.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/
#pragma once

#include <string>
#include <memory>

namespace sysdig
{

/**
 * Interface to an abstract url_fetcher -- an object that clients can use
 * to fetch URLs.  We'll eventually be able to unit test-specific concrete
 * implementaions of this that can serve pre-canned responses without actually
 * spinning up HTTP servers.
 */
class url_fetcher
{
public:
	typedef std::unique_ptr<url_fetcher> ptr;

	virtual ~url_fetcher();

	/**
	 * Fetches the given url and stores the fetched document in the
	 * given body.
	 *
	 * @param[in]  url  The URL to fetch
	 * @param[out] body The body of the fetched URL.
	 *
	 * @returns the HTTP response code
	 */
	virtual int fetch(const std::string& url, std::string& body) = 0;

	/**
	 * Factory method for creating url_fetcher%s that can TCP.
	 *
	 * @returns a pointer to a concrete url_fetcher.
	 */
	static ptr new_fetcher();

	/**
	 * Factory method for creating url_fetcher%s that use UNIX domain
	 * sockets.
	 *
	 * @param[in] socket_filename The filename of the UNIX domain socket.
	 *
	 * @returns a pointer to a concrete url_fetcher.
	 */
	static ptr new_fetcher(const std::string& socket_filename);
};

} // end namespace sysdig
