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
#include "curl_url_fetcher.h"
#include <sstream>
#include <curl/curl.h>

using namespace sysdig;

namespace
{

/**
 * An exception that curl_url_fetcher can throw to indicate errors.
 */
class curl_url_fetcher_exception : public std::exception
{
public:
	curl_url_fetcher_exception(const std::string& message):
		m_message("curl_url_fetcher_exception: " + message)
	{ }

	const char* what() const noexcept override
	{
		return m_message.c_str();
	}

private:
	std::string m_message;
};

/**
 * Handles potentially partial buffer writes from libcurl.  This function
 * will append each chunk to the given body.
 */
size_t write_callback(const char* const ptr,
                      const size_t size,
                      const size_t nmemb,
                      std::stringstream* const body)
{
        const std::size_t total = size * nmemb;

	body->write(ptr, total);

        return total;
}

/**
 * Wrapper over curl_easy_strerror() that returns a std::string
 */
std::string easy_strerror(const CURLcode ecode)
{
	return curl_easy_strerror(ecode);
}

/**
 * Wrapper over curl_multi_strerror() that returns a std::string
 */
std::string multi_strerror(const CURLMcode mcode)
{
	return curl_multi_strerror(mcode);
}

/**
 * Wrapper over curl_easy_setopt() that throws a curl_url_fetcher_exception
 * if the operation fails.
 */
template<typename param_type>
void easy_setopt(CURL* const handle, const CURLoption option, param_type param)
{
	const CURLcode code = curl_easy_setopt(handle, option, param);

	if(code != CURLE_OK)
	{
		throw curl_url_fetcher_exception("Failed to set option: " +
		                                 easy_strerror(code));
	}
}

/**
 * A RAII component to handles adding/removing curl multi handles.
 * This will ensure that curl_multi_remove_handle() is called before objects
 * of this type go out of scope.
 */
class scoped_curl_multi_handle
{
public:
	scoped_curl_multi_handle(CURLM* const curlm, CURL* const curl):
		m_curl(curl),
		m_curlm(curlm),
		m_added(false)
	{
		const CURLMcode code = curl_multi_add_handle(m_curlm, m_curl);

		if(code != CURLM_OK)
		{
			throw curl_url_fetcher_exception(
					"Failed to add multi handler: " +
					multi_strerror(code));
		}
		m_added = true;
	}

	~scoped_curl_multi_handle()
	{
		try
		{
			remove();
		}
		catch(...)
		{
		}
	}

	void remove()
	{
		if(m_added)
		{
			const CURLMcode code = curl_multi_remove_handle(m_curlm,
					                                m_curl);

			if(code != CURLM_OK)
			{
				throw curl_url_fetcher_exception(
						"Failed curl_multi_remove_handle: " +
						multi_strerror(code));
			}

			m_added = false;
		}
	}

private:
	CURL* const m_curl;
	CURLM* const m_curlm;
	bool m_added;
};

} // end namespace

struct curl_url_fetcher::impl
{
	impl(CURL* const curl,
	     CURLM* const curlm,
	     const std::string socket_path = ""):
		m_curl(curl),
		m_curlm(curlm),
		m_socket_path(socket_path)
	{ }

	CURL* const m_curl;
	CURLM* const m_curlm;
	const std::string m_socket_path;
};

curl_url_fetcher::curl_url_fetcher():
	curl_url_fetcher("")
{ }

curl_url_fetcher::curl_url_fetcher(const std::string& socket_filename):
	m_impl(new impl(curl_easy_init(), curl_multi_init(), socket_filename))
{
	if(!m_impl->m_socket_path.empty())
	{
		easy_setopt(m_impl->m_curl,
		            CURLOPT_UNIX_SOCKET_PATH,
			    m_impl->m_socket_path.c_str());
	}
	easy_setopt(m_impl->m_curl, CURLOPT_HTTPGET, 1);
	easy_setopt(m_impl->m_curl, CURLOPT_FOLLOWLOCATION, 1);
	easy_setopt(m_impl->m_curl, CURLOPT_WRITEFUNCTION, write_callback);
}

curl_url_fetcher::~curl_url_fetcher()
{
	curl_multi_cleanup(m_impl->m_curlm);
	curl_easy_cleanup(m_impl->m_curl);
}

int curl_url_fetcher::fetch(const std::string& url, std::string& body)
{
	std::stringstream out;
	CURLcode ecode = CURLE_OK;
	CURLMcode mcode = CURLM_OK;

        easy_setopt(m_impl->m_curl, CURLOPT_URL, url.c_str());
        easy_setopt(m_impl->m_curl, CURLOPT_WRITEDATA, &out);

	scoped_curl_multi_handle multi_handle(m_impl->m_curlm, m_impl->m_curl);

	for(;;)
        {
                int still_running = 42;

                mcode = curl_multi_perform(m_impl->m_curlm, &still_running);
                if(mcode != CURLM_OK)
                {
			throw curl_url_fetcher_exception(
					"Failed curl_multi_perform: " +
					multi_strerror(mcode));
                }

                if(still_running == 0)
                {
                        break;
                }

                int numfds = 0;
                mcode = curl_multi_wait(m_impl->m_curlm, NULL, 0, -1, &numfds);
                if(mcode != CURLM_OK)
                {
			throw curl_url_fetcher_exception(
					"Failed curl_multi_wait: " +
					multi_strerror(mcode));
                }
        }

	multi_handle.remove();

        long http_code = 0;
        ecode = curl_easy_getinfo(m_impl->m_curl, CURLINFO_RESPONSE_CODE, &http_code);
        if(ecode != CURLE_OK)
        {
		throw curl_url_fetcher_exception(
				"Failed to get response code: " +
				easy_strerror(ecode));
        }

	body = out.str();

	return http_code;
}

bool curl_url_fetcher::is_tcp() const
{
	return m_impl->m_socket_path.empty();
}

const std::string& curl_url_fetcher::get_socket_path() const
{
	return m_impl->m_socket_path;
}
