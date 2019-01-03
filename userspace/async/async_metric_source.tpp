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
#include "logger.h"

#include <assert.h>
#include <algorithm>
#include <chrono>
#include <iostream>
#include <list>
#include <string>

namespace sysdig
{

template<typename key_type, typename metric_type>
async_metric_source<key_type, metric_type>::async_metric_source(
		const uint64_t max_wait_ms):
	m_max_wait_ms(max_wait_ms),
	m_thread(),
	m_running(false),
	m_terminate(false),
	m_mutex(),
	m_queue_not_empty_condition(),
	m_metric_map()
{ }

template<typename key_type, typename metric_type>
async_metric_source<key_type, metric_type>::~async_metric_source()
{
	g_logger.log("async_metric_source destructor");
	try
	{
		stop();
	}
	catch(...)
	{
		g_logger.log(std::string(__FUNCTION__) + ": Exception in destructor", sinsp_logger::SEV_ERROR);
	}
}

template<typename key_type, typename metric_type>
uint64_t async_metric_source<key_type, metric_type>::get_max_wait() const
{
	return m_max_wait_ms;
}

template<typename key_type, typename metric_type>
void async_metric_source<key_type, metric_type>::stop()
{
	g_logger.log("ENTRY: sync_metric_source::stop");
	bool join_needed = false;

	{
		std::unique_lock<std::mutex> guard(m_mutex);

		if(m_running)
		{
			m_terminate = true;
			join_needed = true;

			// The async thread might be waiting for new events
			// so wake it up
			m_queue_not_empty_condition.notify_one();
		}
	} // Drop the mutex before join()

	if (join_needed)
	{
		m_thread.join();

		// Remove any pointers from the thread to this object
		// (just to be safe)
		m_thread = std::thread();
	}
	g_logger.log("EXIT: sync_metric_source::stop");
}

template<typename key_type, typename metric_type>
bool async_metric_source<key_type, metric_type>::is_running() const
{
	std::lock_guard<std::mutex> guard(m_mutex);

	return m_running;
}

template<typename key_type, typename metric_type>
void async_metric_source<key_type, metric_type>::run()
{
	g_logger.log("ENTRY: sync_metric_source::run");
	m_running = true;

	while(!m_terminate)
	{
		{
			std::unique_lock<std::mutex> guard(m_mutex);

			while(!m_terminate && m_request_queue.empty())
			{
				g_logger.log("sync_metric_source::run: Waiting for queue item");
				// Wait for something to show up on the queue
				m_queue_not_empty_condition.wait(guard);
			}
		}

		if(!m_terminate)
		{
			g_logger.log("sync_metric_source::run: Invoking run_impl");
			run_impl();
		}
	}

	m_running = false;
	g_logger.log("EXIT: sync_metric_source::run");
}

template<typename key_type, typename metric_type>
bool async_metric_source<key_type, metric_type>::lookup(
		const key_type& key,
		metric_type& metric,
		const callback_handler& callback)
{
	g_logger.log("ENTRY: sync_metric_source::lookup: key:" + key);
	std::unique_lock<std::mutex> guard(m_mutex);

	if(!m_running)
	{
		g_logger.log("sync_metric_source::lookup: starting thread");
		m_thread = std::thread(&async_metric_source::run, this);
	}

	typename metric_map::const_iterator itr = m_metric_map.find(key);
	bool request_complete = (itr != m_metric_map.end()) && itr->second.m_available;

	if(!request_complete)
	{
		g_logger.log("sync_metric_source::lookup: metrics for key not yet available");
		// Haven't made the request yet
		if (itr == m_metric_map.end())
		{
			g_logger.log("sync_metric_source::lookup: first request for metrics");
			m_metric_map[key].m_available = false;
			m_metric_map[key].m_metric = metric;
		}

		// Make request to API and let the async thread know about it
		if (std::find(m_request_queue.begin(),
		              m_request_queue.end(),
		              key) == m_request_queue.end())
		{
			g_logger.log("sync_metric_source::lookup: adding work to queue");
			m_request_queue.push_back(key);
			m_queue_not_empty_condition.notify_one();
		}

		//
		// If the client code is willing to wait a short amount of time
		// to satisfy the request, then wait for the async thread to
		// pick up the newly-added request and execute it.  If
		// processing that request takes too much time, then we'll
		// not be able to return the metric information on this call,
		// and the async thread will continue handling the request so
		// that it'll be available on the next call.
		//
		if (m_max_wait_ms > 0)
		{
			m_metric_map[key].m_available_condition.wait_for(
					guard,
					std::chrono::milliseconds(m_max_wait_ms));

			itr = m_metric_map.find(key);
			request_complete = (itr != m_metric_map.end()) && itr->second.m_available;
		}
	}

	g_logger.log("sync_metric_source::lookup: request_complete: " + std::to_string(request_complete));
	if(request_complete)
	{
		metric = itr->second.m_metric;
		m_metric_map.erase(key);
	}
	else
	{
		g_logger.log("sync_metric_source::lookup: saving callback");
		m_metric_map[key].m_callback = callback;
	}

	return request_complete;
}

template<typename key_type, typename metric_type>
std::size_t async_metric_source<key_type, metric_type>::queue_size() const
{
	std::lock_guard<std::mutex> guard(m_mutex);
	return m_request_queue.size();
}

template<typename key_type, typename metric_type>
key_type async_metric_source<key_type, metric_type>::dequeue_next_key()
{
	g_logger.log("ENTRY: sync_metric_source::dequeue_next_key");
	std::lock_guard<std::mutex> guard(m_mutex);
	key_type key = m_request_queue.front();

	m_request_queue.pop_front();

	g_logger.log("EXIT: sync_metric_source::dequeue_next_key");
	return key;
}

template<typename key_type, typename metric_type>
metric_type async_metric_source<key_type, metric_type>::get_metrics(const key_type& key)
{
	std::lock_guard<std::mutex> guard(m_mutex);

	return m_metric_map[key].m_metric;
}

template<typename key_type, typename metric_type>
void async_metric_source<key_type, metric_type>::store_metric(
		const key_type& key,
		const metric_type& metric)
{
	g_logger.log("ENTRY: sync_metric_source::store_metric");
	std::lock_guard<std::mutex> guard(m_mutex);

	if (m_metric_map[key].m_callback)
	{
		g_logger.log("sync_metric_source::store_metric: Invoking callback");
		m_metric_map[key].m_callback(key, metric);
		m_metric_map.erase(key);
	}
	else
	{
		g_logger.log("sync_metric_source::store_metric: Saving metrics for later");
		m_metric_map[key].m_metric = metric;
		m_metric_map[key].m_available = true;
		m_metric_map[key].m_available_condition.notify_one();
	}
	g_logger.log("EXIT: sync_metric_source::store_metric");
}

} // end namespace sysdig
