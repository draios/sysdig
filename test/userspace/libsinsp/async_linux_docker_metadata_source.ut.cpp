/**
 * @file
 *
 * Fill in a short overview of the file's content
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "async_linux_docker_metadata_source.h"
#include "test_helpers/web_server_helper.h"

#include <chrono>
#include <fstream>
#include <sstream>
#include <thread>
#include <unistd.h>

#include <gtest.h>
#include <Poco/StreamCopier.h>

#if defined(LOCAL_DEBUG)
#       include<cstdio>
#       define LOG(fmt, ...) fprintf(stderr, "[%s]:%d: " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#       define LOG(fmt, ...) do { } while(false)
#endif

using namespace test;
using namespace sysdig;

class sinsp_container_manager;

namespace
{

const std::string s_container_id = "b646c6d7cad09218238eb0ccf72d78024bc4e742a11b778c1637575121abcdd5";
const std::string s_image_id = "fe52b035c0bdc374d688ec285efc80a349b34e188031408a037c171cadf3e47b";

/**
 * Read the content of the file with the given filename into the given
 * content.
 *
 * @param[in] filename The name of the file to read
 * @param[out] content On success, returns the output of the file
 *
 * @returns true if the file can be opened for reading, false otherwise.
 */
bool read_file(const std::string& filename, std::string& content)
{
	std::ifstream in(filename);

	if(!in)
	{
		return false;
	}

	std::ostringstream out;

	Poco::StreamCopier::copyStream(in, out);

	content = std::move(out.str());

	return true;
}

/**
 * Base class for all tests; used to set up a suite-wide fixture.
 */
class async_linux_docker_metadata_source_test : public testing::Test
{
public:
	/**
	 * Allocate the web_server_helper before any test run.
	 */
	static void SetUpTestCase()
	{
		std::string content;

		ASSERT_EQ(s_server_helper, nullptr);
		s_server_helper = new web_server_helper();

		ASSERT_TRUE(read_file("./resources/docker_container_" + s_container_id + ".json",
		                      content));
		s_server_helper->set_content("/v1.24/containers/" + s_container_id + "/json",
		                             content);

		ASSERT_TRUE(read_file("./resources/docker_image_" + s_image_id + ".json",
		                      content));

		s_server_helper->set_content("/v1.24/images/" + s_image_id + "/json?digests=1",
		                             content);
	}

	/**
	 * Deallocate the web_server_helper after all tests have finished.
	 */
	static void TearDownTestCase()
	{
		ASSERT_NE(s_server_helper, nullptr);
		delete s_server_helper;
	}

protected:
	/**
	 * Enable the tests to get the server without being able to muck
	 * with the pointer.
	 */
	web_server_helper& get_docker()
	{
		return *s_server_helper;
	}

	/**
	 * Returns true if the given collection contains the given element
	 *
	 * @tparam collection The type of collection to search
	 * @tparam element_type The type of element in the collection
	 *
	 * @param[in] collection The collection to search
	 * @param[in] element    The element for which to search
	 *
	 * @returns true if the element is found in the collection,
	 *          false otherwise.
	 */
	template<typename collection_type, typename element_type>
	bool contains(const collection_type& collection, const element_type& element)
	{
		return (std::find(collection.begin(), collection.end(), element) != collection.end());
	}

private:
	static web_server_helper* s_server_helper;
};

web_server_helper* async_linux_docker_metadata_source_test::s_server_helper;

} // end namespace


/**
 * Ensure that the constructor puts the metadata source in the expected
 * initial state.
 */
TEST_F(async_linux_docker_metadata_source_test, constructor)
{
	async_linux_docker_metadata_source source;

	ASSERT_EQ(async_linux_docker_metadata_source::DEFAULT_API_VERSION,
	          source.get_api_version());
	ASSERT_EQ(async_linux_docker_metadata_source::DEFAULT_DOCKER_SOCKET_PATH,
	          source.get_socket_path());
	ASSERT_TRUE(source.query_image_info());
}

/**
 * Ensure that if the client specifies custom values for the api version and
 * the socket path, that those values are recorded.
 */
TEST_F(async_linux_docker_metadata_source_test, constructor_custom_values)
{
	const bool query_image_info = true;
	const std::string api_version = "v10";
	const std::string socket_path = "/some/path.sock";

	async_linux_docker_metadata_source source(query_image_info,
	                                          socket_path,
	                                          api_version);

	ASSERT_EQ(api_version, source.get_api_version());
	ASSERT_EQ(socket_path, source.get_socket_path());
	ASSERT_EQ(query_image_info, source.query_image_info());
}

/**
 * Ensure that set_query_image_info() updates the image info query state.
 */
TEST_F(async_linux_docker_metadata_source_test, query_image_info)
{
	async_linux_docker_metadata_source source;

	source.set_query_image_info(false);
	ASSERT_FALSE(source.query_image_info());

	source.set_query_image_info(true);
	ASSERT_TRUE(source.query_image_info());
}

/**
 * Ensure that lookup_metrics() exhibits the expected behavior.  Specifically,
 * we expect the first call to lookup_metrics() to fail, and to kick off the
 * background thread.  We expect that thread, within a reasonable amount of
 * time, to fetch the desired content, and to parse it.  We expect a subsequent
 * call to lookup_metrics() to return the parsed metrics.
 */
TEST_F(async_linux_docker_metadata_source_test, lookup_metrics)
{
	const bool query_image_info = true;
	std::shared_ptr<sinsp_container_info> container_info(new sinsp_container_info());
	sinsp_container_manager* manager = nullptr;

	container_info->m_id = s_container_id;
	container_info->m_type = CT_DOCKER;

	docker_metadata metadata(manager, container_info);
	async_linux_docker_metadata_source source(query_image_info,
			                          get_docker().get_socket_path());

	// The first call to lookup() will kick off the async lookup.  The
	// Docker metadata fetcher will not block waiting for a response, so
	// the first call for a given id should always fail.
	ASSERT_FALSE(source.lookup(container_info->m_id, metadata));

	// We don't know exactly how long it will take for the async fetcher to
	// contact the docker server helper, for the server helper to return
	// the precanned response, and for the async fetcher to parse the
	// results.  We should be able to poll for the response.  We'll poll
	// for up to a max of 10s -- if it takes more than 10s, we'll assume
	// something has gone horribly wrong.
	const int MAX_WAIT_TIME_SECS = 10;
	const int FRACTION_OF_SECOND = 10;
	bool eventually_successful = false;

	for (int i = 0; !eventually_successful && i < (MAX_WAIT_TIME_SECS * FRACTION_OF_SECOND); ++i)
	{
		const int ONE_SEC_MS = 1000;
		std::this_thread::sleep_for(std::chrono::milliseconds(ONE_SEC_MS / FRACTION_OF_SECOND));
		eventually_successful = source.lookup(container_info->m_id, metadata);
	}

	ASSERT_TRUE(eventually_successful);
	container_info = metadata.m_container_info;

	// Make sure that we correctly parsed the interesting information
	ASSERT_EQ(container_info->m_id, s_container_id);
	ASSERT_EQ(container_info->m_type, CT_DOCKER);
	ASSERT_EQ(container_info->m_name, "opengrok");
	ASSERT_EQ(container_info->m_image, "opengrok/docker:latest");
	ASSERT_EQ(container_info->m_imageid, s_image_id);
	ASSERT_EQ(container_info->m_imagerepo, "opengrok/docker");
	ASSERT_EQ(container_info->m_imagetag, "latest");
	ASSERT_EQ(container_info->m_imagedigest, "");
	ASSERT_EQ(container_info->m_container_ip, 2886795267);
	ASSERT_FALSE(container_info->m_privileged);

	ASSERT_NE(container_info->m_mounts.begin(), container_info->m_mounts.end());
	{
		auto itr = container_info->m_mounts.begin();

		ASSERT_EQ(itr->m_source, "/home/user/.opengrok");
		ASSERT_EQ(itr->m_dest, "/src");
		ASSERT_EQ(itr->m_mode, "");
		ASSERT_TRUE(itr->m_rdwr);
		ASSERT_EQ(itr->m_propagation, "rprivate");
	}

	ASSERT_NE(container_info->m_port_mappings.begin(), container_info->m_port_mappings.end());
	{
		auto itr = container_info->m_port_mappings.begin();

		ASSERT_EQ(itr->m_host_ip, 0);
		ASSERT_EQ(itr->m_host_port, 8080);
		ASSERT_EQ(itr->m_container_port, 8080);
	}

	ASSERT_TRUE(container_info->m_labels.empty());

	ASSERT_NE(container_info->m_env.begin(), container_info->m_env.end());
	{
		ASSERT_TRUE(contains(container_info->m_env, "REINDEX=0"));
		ASSERT_TRUE(contains(container_info->m_env, "LANG=C.UTF-8"));
		ASSERT_TRUE(contains(container_info->m_env, "JAVA_HOME=/docker-java-home/jre"));
		ASSERT_TRUE(contains(container_info->m_env, "JAVA_VERSION=8u181"));
		ASSERT_TRUE(contains(container_info->m_env, "JAVA_DEBIAN_VERSION=8u181-b13-2~deb9u1"));
		ASSERT_TRUE(contains(container_info->m_env, "CATALINA_HOME=/usr/local/tomcat"));
		ASSERT_TRUE(contains(container_info->m_env, "TOMCAT_NATIVE_LIBDIR=/usr/local/tomcat/native-jni-lib"));
		ASSERT_TRUE(contains(container_info->m_env, "LD_LIBRARY_PATH=/usr/local/tomcat/native-jni-lib"));
		ASSERT_TRUE(contains(container_info->m_env, "OPENSSL_VERSION=1.1.0j-1~deb9u1"));
		ASSERT_TRUE(contains(container_info->m_env, "TOMCAT_MAJOR=9"));
		ASSERT_TRUE(contains(container_info->m_env, "TOMCAT_VERSION=9.0.14"));
	}

	ASSERT_EQ(container_info->m_mesos_task_id, std::string());
	ASSERT_EQ(container_info->m_memory_limit, 0);
	ASSERT_EQ(container_info->m_swap_limit, 0);
	ASSERT_EQ(container_info->m_cpu_shares, 1024);
	ASSERT_EQ(container_info->m_cpu_quota, 0);
	ASSERT_EQ(container_info->m_cpu_period, 100000);
	ASSERT_EQ(container_info->m_sysdig_agent_conf, std::string());
	ASSERT_EQ(container_info->m_metadata_deadline, 0);
}

