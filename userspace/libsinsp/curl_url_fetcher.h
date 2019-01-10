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

#include "url_fetcher.h"
#include <memory>

namespace sysdig
{

/**
 * A concrete url_fetcher implemented using libcurl.
 */
class curl_url_fetcher : public url_fetcher
{
public:
	/**
	 * Initialize this curl_url_fetcher for fetching URLs via TCP.
	 */
	curl_url_fetcher();

	/**
	 * Initialize this curl_url_fetcher for fetching URLs via UNIX
	 * domain sockets.
	 */
	curl_url_fetcher(const std::string& socket_filename);

	virtual ~curl_url_fetcher();

	/**
	 * Fetch the given url and return its body in the given body.
	 *
	 * @param[in]  url The URL to fetch
	 * @param[out] body On success, the body of the requested URL.
	 *
	 * @returns the HTTP status code returned by the far-end
	 */
	int fetch(const std::string& url, std::string& body) override;

	/**
	 * Returns true if this curl_url_fetcher will fetch URLs via TCP,
	 * false otherwise.
	 */
	bool is_tcp() const;

	/**
	 * Returns the UNIX domain socket that this curl_url_fetcher will
	 * use for requests.  This method is meaningful only if is_tcp()
	 * returns false.
	 */
	const std::string& get_socket_path() const;

private:
	struct impl;
	std::unique_ptr<impl> m_impl;
};

} // end namespace sysdig
