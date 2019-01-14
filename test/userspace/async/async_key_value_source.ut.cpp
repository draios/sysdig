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
#include "async_key_value_source.h"

#include <string>
#include <gtest.h>

using namespace sysdig;

namespace
{

/**
 * Intermediate realization of async_key_value_source that can return pre-canned
 * results.
 */
class precanned_metadata_source : public async_key_value_source<std::string, std::string> 
{
public:
	const static uint64_t FOREVER_MS;

	precanned_metadata_source(const uint64_t max_wait_ms,
	                          const uint64_t ttl_ms = FOREVER_MS)
		: async_key_value_source(max_wait_ms, ttl_ms),
		m_responses()
	{ }

	void set_response(const std::string& key, const std::string& response)
	{
		m_responses[key] = response;
	}

	std::string get_response(const std::string& key)
	{
		return m_responses[key];
	}

private:
	std::map<std::string, std::string> m_responses;
};
const uint64_t precanned_metadata_source::FOREVER_MS = static_cast<uint64_t>(~0L);

/**
 * Realization of async_key_value_source that returns results without delay.
 */
class immediate_metadata_source : public precanned_metadata_source
{
public:
	const static uint64_t MAX_WAIT_TIME_MS;

	immediate_metadata_source():
		precanned_metadata_source(MAX_WAIT_TIME_MS)
	{ }

protected:
	virtual void run_impl() override
	{
		while(queue_size() > 0)
		{
			const std::string key = dequeue_next_key();
			store_metadata(key, get_response(key));
		}
	}
};
const uint64_t immediate_metadata_source::MAX_WAIT_TIME_MS = 5000;

/**
 * Realization of async_key_value_source that returns results with some
 * specified delay.
 */
class delayed_metadata_source : public precanned_metadata_source
{
public:
	const static uint64_t MAX_WAIT_TIME_MS;

	delayed_metadata_source(const uint64_t delay_ms,
	                        const uint64_t ttl_ms = FOREVER_MS):
		precanned_metadata_source(MAX_WAIT_TIME_MS, ttl_ms),
		m_delay_ms(delay_ms)
	{ }

protected:
	virtual void run_impl() override
	{
		while(queue_size() > 0)
		{
			const std::string key = dequeue_next_key();

			std::this_thread::sleep_for(std::chrono::milliseconds(m_delay_ms));

			store_metadata(key, get_response(key));
		}
	}

private:
	uint64_t m_delay_ms;
};
const uint64_t delayed_metadata_source::MAX_WAIT_TIME_MS = 0;

}

/**
 * Ensure that a concrete async_key_value_source is in the expected initial
 * state after construction.
 */
TEST(async_key_value_source_test, construction)
{
	immediate_metadata_source source;

	ASSERT_EQ(immediate_metadata_source::MAX_WAIT_TIME_MS, source.get_max_wait());
	ASSERT_EQ(precanned_metadata_source::FOREVER_MS, source.get_ttl());
	ASSERT_FALSE(source.is_running());
}

/**
 * Ensure that if a concrete async_key_value_source returns the metadata before
 * the timeout, that the lookup() method returns true, and that it returns
 * the metadata in the output parameter.
 */
TEST(async_key_value_source_test, lookup_key_immediate_return)
{
	const std::string key = "foo";
	const std::string metadata = "bar";
	std::string response = "response-not-set";

	immediate_metadata_source source;

	// Seed the precanned response
	source.set_response(key, metadata);

	ASSERT_TRUE(source.lookup(key, response));
	ASSERT_EQ(metadata, response);
	ASSERT_TRUE(source.is_running());
}

/**
 * Ensure that if a concrete async_key_value_source cannot return the result
 * before the timeout, and if the client did not provide a callback, that
 * calling lookup() after the result it available returns the value.
 */
TEST(async_key_value_source_test, lookup_key_delayed_return_second_call)
{
	const uint64_t DELAY_MS = 50;
	const std::string key = "mykey";
	const std::string metadata = "myvalue";

	delayed_metadata_source source(DELAY_MS);

	std::string response = "response-not-set";
	bool response_found;

	// Seed the precanned response
	source.set_response(key, metadata);

	response_found = source.lookup(key, response);

	ASSERT_FALSE(response_found);

	// Since we didn't supply a callback, a subsequent call to lookup
	// after the metadata collection is complete will return the previously
	// collected metadata.  We know that the delayed_metadata_source is
	// waiting for DELAY_MS, so wait longer than that.
	std::this_thread::sleep_for(std::chrono::milliseconds(2 * DELAY_MS));

	// Response should now be available
	response_found = source.lookup(key, response);

	ASSERT_TRUE(response_found);
	ASSERT_EQ(metadata, response);
}

/**
 * Ensure that if a concrete async_key_value_source cannot return the result
 * before the timeout, and if the client did provide a callback, that the
 * callback is invoked with the metadata once they're avaialble.
 */
TEST(async_key_value_source_test, look_key_delayed_async_callback)
{
	const uint64_t DELAY_MS = 50;
	const std::string key = "mykey";
	const std::string metadata = "myvalue";

	delayed_metadata_source source(DELAY_MS);

	std::string sync_response = "sync-response-not-set";
	std::string async_response = "async-response-not-set";
	bool response_found;

	// Seed the precanned response
	source.set_response(key, metadata);

	response_found = source.lookup(key,
	                               sync_response,
	                               [&async_response](const std::string& key,
	                                                 const std::string& value)
	{
		async_response = value;
	});

	ASSERT_FALSE(response_found);

	// Since we supplied a callback, the delayed_metadata_source should
	// complete after DELAY_MS, and it should immediately call our
	// callback.  Wait long enough for that to happen.
	std::this_thread::sleep_for(std::chrono::milliseconds(5 * DELAY_MS));

	ASSERT_EQ(metadata, async_response);
}

/**
 * Ensure that "old" results are pruned
 */
TEST(async_key_value_source_test, prune_old_metadata)
{
	const uint64_t DELAY_MS = 0;
	const uint64_t TTL_MS = 20;

	const std::string key1 = "mykey1";
	const std::string metadata1 = "myvalue1";

	const std::string key2 = "mykey2";
	const std::string metadata2 = "myvalue2";

	delayed_metadata_source source(DELAY_MS, TTL_MS);
	std::string response = "response-not-set";

	// Seed the precanned response
	source.set_response(key1, metadata1);
	source.set_response(key2, metadata2);

	// Since DELAY_MS is 0, then lookup should return false immediately,
	// and should almost immediately add the result to the cache
	ASSERT_FALSE(source.lookup(key1, response));

	// Wait long enough for the old entry to require pruning
	std::this_thread::sleep_for(std::chrono::milliseconds(2 * TTL_MS));

	// Request the other key.  This should wake up the thread and actually
	// preform the pruning.
	ASSERT_FALSE(source.lookup(key2, response));

	// Wait long enough for the async thread to get woken up and to
	// prune the old entry
	std::this_thread::sleep_for(std::chrono::milliseconds(TTL_MS));

	// Since the first key should have been pruned, a second call to
	// fetch the first key should also return false.
	ASSERT_FALSE(source.lookup(key1, response));
}
