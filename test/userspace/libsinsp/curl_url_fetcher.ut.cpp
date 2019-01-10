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
#include "test_helpers/web_server_helper.h"
#include <gtest.h>

using namespace sysdig;
using namespace test;

namespace
{

const int HTTP_OK = 200;

} // end namespace;

/*
 * Base class for all tests; used to set up a suite-wide fixture.
 */
class curl_url_fetcher_test : public testing::Test
{
public:
	/**
	 * Allocate the web_server_helper before any test run.
	 */
	static void SetUpTestCase()
	{
		ASSERT_EQ(s_unix_server_helper, nullptr);
		s_unix_server_helper = new web_server_helper();

		ASSERT_EQ(s_tcp_server_helper, nullptr);
		s_tcp_server_helper = new web_server_helper(
				web_server_helper::SELECT_EPHEMERAL_PORT);
	}

	/**
	 * Deallocate the web_server_helper after all tests have finished.
	 */
	static void TearDownTestCase()
	{
		ASSERT_NE(s_unix_server_helper, nullptr);
		delete s_unix_server_helper;
		s_unix_server_helper = nullptr;

		ASSERT_NE(s_tcp_server_helper, nullptr);
		delete s_tcp_server_helper;
		s_tcp_server_helper = nullptr;
	}

	/**
	 * Clear any entries from the helpers.
	 */
	void TearDown()
	{
		s_unix_server_helper->reset();
		s_tcp_server_helper->reset();
	}

protected:
	/**
	 * Enable the tests to get the UNIX domain socket server helper without
	 * being able to muck with the pointer.
	 */
	web_server_helper& get_unix_server()
	{
		return *s_unix_server_helper;
	}

	/**
	 * Enable the tests to get the TCP server helper without
	 * being able to muck with the pointer.
	 */
	web_server_helper& get_tcp_server()
	{
		return *s_tcp_server_helper;
	}


private:
	static web_server_helper* s_unix_server_helper;
	static web_server_helper* s_tcp_server_helper;
};

web_server_helper* curl_url_fetcher_test::s_unix_server_helper;
web_server_helper* curl_url_fetcher_test::s_tcp_server_helper;

/**
 * Ensure that the default constructor creates a curl_url_fetcher for TCP.
 */
TEST_F(curl_url_fetcher_test, tcp_constructor)
{
	curl_url_fetcher fetcher;

	ASSERT_TRUE(fetcher.is_tcp());
	ASSERT_EQ(fetcher.get_socket_path(), std::string());
}

/**
 * Ensure that the parameterized constructor creates a curl_url_fetcher for
 * UNIX domain sockets.
 */
TEST_F(curl_url_fetcher_test, unix_domain_constructor)
{
	curl_url_fetcher fetcher(get_unix_server().get_socket_path());

	ASSERT_FALSE(fetcher.is_tcp());
	ASSERT_EQ(fetcher.get_socket_path(), get_unix_server().get_socket_path());
}

/**
 * Ensure that a curl_url_fetcher can fetch a document via TCP.
 */
TEST_F(curl_url_fetcher_test, fetch_tcp)
{
	const std::string path = "/foo";
	const std::string expected_content = "bar";
	const std::string url = "http://localhost:" +
	                        std::to_string(get_tcp_server().get_port()) +
				path;
	std::string actual_content;
	curl_url_fetcher fetcher;

	get_tcp_server().set_content(path, expected_content);

	ASSERT_EQ(fetcher.fetch(url, actual_content), HTTP_OK);
	ASSERT_EQ(expected_content, actual_content);
}

/**
 * Ensure that a curl_url_fetcher can fetch a document via a UNIX domain socket.
 */
TEST_F(curl_url_fetcher_test, fetch_unix)
{
	const std::string path = "/bar";
	const std::string expected_content = "foo";
	const std::string url = "http://localhost:" + path;
	std::string actual_content;
	curl_url_fetcher fetcher(get_unix_server().get_socket_path());

	get_unix_server().set_content(path, expected_content);

	ASSERT_EQ(fetcher.fetch(url, actual_content), HTTP_OK);
	ASSERT_EQ(expected_content, actual_content);
}
