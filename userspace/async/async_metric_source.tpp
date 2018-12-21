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
	try
	{
		stop();
	}
	catch(...)
	{
		// TODO: Ignore? Log?
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
	m_running = true;

	while(!m_terminate)
	{
		{
			std::unique_lock<std::mutex> guard(m_mutex);

			while(!m_terminate && m_request_queue.empty())
			{
				// Wait for something to show up on the queue
				m_queue_not_empty_condition.wait(guard);
			}
		}

		if(!m_terminate)
		{
			run_impl();
		}
	}

	m_running = false;
}

template<typename key_type, typename metric_type>
bool async_metric_source<key_type, metric_type>::lookup(
		const key_type& key,
		metric_type& metric,
		const callback_handler& callback)
{
	std::unique_lock<std::mutex> guard(m_mutex);

	if(!m_running)
	{
		m_thread = std::thread(&async_metric_source::run, this);
	}

	typename metric_map::const_iterator itr = m_metric_map.find(key);
	bool found = (itr != m_metric_map.end()) && itr->second.m_available;

	if(!found)
	{
		if (itr == m_metric_map.end())
		{
			m_metric_map[key].m_available = false;
		}

		// Make request to API and let the async thread know about it
		if (std::find(m_request_queue.begin(),
		              m_request_queue.end(),
		              key) == m_request_queue.end())
		{
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
			found = (itr != m_metric_map.end()) && itr->second.m_available;
		}
	}

	if(found)
	{
		metric = itr->second.m_metric;
		m_metric_map.erase(key);
	}
	else
	{
		m_metric_map[key].m_callback = callback;
	}

	return found;
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
	std::lock_guard<std::mutex> guard(m_mutex);
	key_type key = m_request_queue.front();

	m_request_queue.pop_front();

	return key;
}

template<typename key_type, typename metric_type>
void async_metric_source<key_type, metric_type>::store_metric(
		const key_type& key,
		const metric_type& metric)
{
	std::lock_guard<std::mutex> guard(m_mutex);

	if (m_metric_map[key].m_callback)
	{
		m_metric_map[key].m_callback(key, metric);
		m_metric_map.erase(key);
	}
	else
	{
		m_metric_map[key].m_metric = metric;
		m_metric_map[key].m_available = true;
		m_metric_map[key].m_available_condition.notify_one();
	}
}

} // end namespace sysdig
