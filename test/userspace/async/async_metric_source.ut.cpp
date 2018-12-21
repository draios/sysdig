/**
 * @file
 *
 * Fill in a short overview of the file's content
 *
 * @copyright Copyright (c) 2018 Draios Inc. dba Sysdig, All Rights Reserved
 */
#include "async_metric_source.h"

#include <string>
#include <gtest.h>

using namespace sysdig;

namespace
{

/**
 * Intermediate realization of async_metric_source that can return pre-canned
 * results.
 */
class precanned_metric_source : public async_metric_source<std::string, std::string> 
{
public:
	precanned_metric_source(const uint64_t max_wait_ms)
		: async_metric_source(max_wait_ms),
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

/**
 * Realization of async_metric_source that returns results without delay.
 */
class immediate_metric_source : public precanned_metric_source
{
public:
	const static uint64_t MAX_WAIT_TIME_MS;

	immediate_metric_source():
		precanned_metric_source(MAX_WAIT_TIME_MS)
	{ }

protected:
	virtual void run_impl() override
	{
		while(queue_size() > 0)
		{
			const std::string key = dequeue_next_key();
			store_metric(key, get_response(key));
		}
	}
};
const uint64_t immediate_metric_source::MAX_WAIT_TIME_MS = 5000;

/**
 * Realization of async_metric_source that returns results with some
 * specified delay.
 */
class delayed_metric_source : public precanned_metric_source
{
public:
	const static uint64_t MAX_WAIT_TIME_MS;

	delayed_metric_source(const uint64_t delay_ms):
		precanned_metric_source(MAX_WAIT_TIME_MS),
		m_delay_ms(delay_ms)
	{ }

protected:
	virtual void run_impl() override
	{
		while(queue_size() > 0)
		{
			const std::string key = dequeue_next_key();

			std::this_thread::sleep_for(std::chrono::milliseconds(m_delay_ms));

			store_metric(key, get_response(key));
		}
	}

private:
	uint64_t m_delay_ms;
};
const uint64_t delayed_metric_source::MAX_WAIT_TIME_MS = 0;

}

/**
 * Ensure that a concrete async_metric_source is in the expected initial state
 * after construction.
 */
TEST(async_metric_source, construction)
{
	immediate_metric_source source;

	ASSERT_EQ(immediate_metric_source::MAX_WAIT_TIME_MS, source.get_max_wait());
	ASSERT_FALSE(source.is_running());
}

/**
 * Ensure that if a concrete async_metric_source returns the metrics before
 * the timeout, that the lookup() method returns true, and that it returns
 * the metrics in the output parameter.
 */
TEST(async_metric_source, lookup_key_immediate_return)
{
	const std::string key = "foo";
	const std::string metric = "bar";
	std::string response = "response-not-set";
	bool response_found;

	immediate_metric_source source;

	// Seed the precanned response
	source.set_response(key, metric);

	response_found = source.lookup(key, response);

	ASSERT_TRUE(response_found);
	ASSERT_EQ(metric, response);
	ASSERT_TRUE(source.is_running());
}

/**
 * Ensure that if a concrete async_metric_source cannot return the result
 * before the timeout, and if the client did not provide a callback, that
 * calling lookup() after the result it available returns the value.
 */
TEST(async_metric_source, lookup_key_delayed_return_second_call)
{
	const uint64_t DELAY_MS = 50;
	const std::string key = "mykey";
	const std::string metric = "myvalue";

	delayed_metric_source source(DELAY_MS);

	std::string response = "response-not-set";
	bool response_found;

	// Seed the precanned response
	source.set_response(key, metric);

	response_found = source.lookup(key, response);

	ASSERT_FALSE(response_found);

	// Since we didn't supply a callback, a subsequent call to lookup
	// after the metric collection is complete will return the previously
	// collected metric.  We know that the delayed_metric_source is
	// waiting for DELAY_MS, so wait longer than that.
	std::this_thread::sleep_for(std::chrono::milliseconds(2 * DELAY_MS));

	// Response should now be available
	response_found = source.lookup(key, response);

	ASSERT_TRUE(response_found);
	ASSERT_EQ(metric, response);
}

/**
 * Ensure that if a concrete async_metric_source cannot return the result
 * before the timeout, and if the client did provide a callback, that the
 * callback is invoked with the metrics once they're avaialble.
 */
TEST(async_metric_source, look_key_delayed_async_callback)
{
	const uint64_t DELAY_MS = 50;
	const std::string key = "mykey";
	const std::string metric = "myvalue";

	delayed_metric_source source(DELAY_MS);

	std::string sync_response = "sync-response-not-set";
	std::string async_response = "async-response-not-set";
	bool response_found;

	// Seed the precanned response
	source.set_response(key, metric);

	response_found = source.lookup(key,
	                               sync_response,
	                               [&async_response](const std::string& key,
	                                                 const std::string& value)
	{
		async_response = value;
	});

	ASSERT_FALSE(response_found);

	// Since we supplied a callback, the delayed_metric_source should
	// complete after DELAY_MS, and it should immediately call our
	// callback.  Wait long enough for that to happen.
	std::this_thread::sleep_for(std::chrono::milliseconds(5 * DELAY_MS));

	ASSERT_EQ(metric, async_response);
}
