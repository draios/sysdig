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

template<typename key_type, typename metadata_type>
async_metadata_source<key_type, metadata_type>::async_metadata_source(
		const uint64_t max_wait_ms,
		const uint64_t ttl_ms):
	m_max_wait_ms(max_wait_ms),
	m_ttl_ms(ttl_ms),
	m_thread(),
	m_running(false),
	m_terminate(false),
	m_mutex(),
	m_queue_not_empty_condition(),
	m_metadata_map()
{ }

template<typename key_type, typename metadata_type>
async_metadata_source<key_type, metadata_type>::~async_metadata_source()
{
	try
	{
		stop();
	}
	catch(...)
	{
		g_logger.log(std::string(__FUNCTION__) +
		             ": Exception in destructor",
		             sinsp_logger::SEV_ERROR);
	}
}

template<typename key_type, typename metadata_type>
uint64_t async_metadata_source<key_type, metadata_type>::get_max_wait() const
{
	return m_max_wait_ms;
}

template<typename key_type, typename metadata_type>
uint64_t async_metadata_source<key_type, metadata_type>::get_ttl() const
{
	return m_ttl_ms;
}

template<typename key_type, typename metadata_type>
void async_metadata_source<key_type, metadata_type>::stop()
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

template<typename key_type, typename metadata_type>
bool async_metadata_source<key_type, metadata_type>::is_running() const
{
	std::lock_guard<std::mutex> guard(m_mutex);

	return m_running;
}

template<typename key_type, typename metadata_type>
void async_metadata_source<key_type, metadata_type>::run()
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

			prune_stale_requests();
		}

		if(!m_terminate)
		{
			run_impl();
		}
	}

	m_running = false;
}

template<typename key_type, typename metadata_type>
bool async_metadata_source<key_type, metadata_type>::lookup(
		const key_type& key,
		metadata_type& metadata,
		const callback_handler& callback)
{
	std::unique_lock<std::mutex> guard(m_mutex);

	if(!m_running)
	{
		m_thread = std::thread(&async_metadata_source::run, this);
	}

	typename metadata_map::const_iterator itr = m_metadata_map.find(key);
	bool request_complete = (itr != m_metadata_map.end()) && itr->second.m_available;

	if(!request_complete)
	{
		// Haven't made the request yet
		if (itr == m_metadata_map.end())
		{
			m_metadata_map[key].m_available = false;
			m_metadata_map[key].m_metadata = metadata;
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
		// not be able to return the metadata information on this call,
		// and the async thread will continue handling the request so
		// that it'll be available on the next call.
		//
		if (m_max_wait_ms > 0)
		{
			m_metadata_map[key].m_available_condition.wait_for(
					guard,
					std::chrono::milliseconds(m_max_wait_ms));

			itr = m_metadata_map.find(key);
			request_complete = (itr != m_metadata_map.end()) && itr->second.m_available;
		}
	}

	if(request_complete)
	{
		metadata = itr->second.m_metadata;
		m_metadata_map.erase(key);
	}
	else
	{
		m_metadata_map[key].m_callback = callback;
	}

	return request_complete;
}

template<typename key_type, typename metadata_type>
std::size_t async_metadata_source<key_type, metadata_type>::queue_size() const
{
	std::lock_guard<std::mutex> guard(m_mutex);
	return m_request_queue.size();
}

template<typename key_type, typename metadata_type>
key_type async_metadata_source<key_type, metadata_type>::dequeue_next_key()
{
	std::lock_guard<std::mutex> guard(m_mutex);
	key_type key = m_request_queue.front();

	m_request_queue.pop_front();

	return key;
}

template<typename key_type, typename metadata_type>
metadata_type async_metadata_source<key_type, metadata_type>::get_metadata(
		const key_type& key)
{
	std::lock_guard<std::mutex> guard(m_mutex);

	return m_metadata_map[key].m_metadata;
}

template<typename key_type, typename metadata_type>
void async_metadata_source<key_type, metadata_type>::store_metadata(
		const key_type& key,
		const metadata_type& metadata)
{
	std::lock_guard<std::mutex> guard(m_mutex);

	if (m_metadata_map[key].m_callback)
	{
		m_metadata_map[key].m_callback(key, metadata);
		m_metadata_map.erase(key);
	}
	else
	{
		m_metadata_map[key].m_metadata = metadata;
		m_metadata_map[key].m_available = true;
		m_metadata_map[key].m_available_condition.notify_one();
	}
}

/**
 * Prune any "old" outstanding requests.  This method expect that the caller
 * is holding m_mutex.
 */
template<typename key_type, typename metadata_type>
void async_metadata_source<key_type, metadata_type>::prune_stale_requests()
{
	// Avoid both iterating over and modifying the map by saving a list
	// of keys to prune.
	std::vector<key_type> keys_to_prune;

	for(auto i = m_metadata_map.begin();
	    !m_terminate && (i != m_metadata_map.end());
	    ++i)
	{
		const auto now = std::chrono::steady_clock::now();

		const auto age_ms =
			std::chrono::duration_cast<std::chrono::milliseconds>(
					now - i->second.m_start_time).count();

		if(age_ms > m_ttl_ms)
		{
			keys_to_prune.push_back(i->first);
		}
	}

	for(auto i = keys_to_prune.begin();
	    !m_terminate && (i != keys_to_prune.end());
	    ++i)
	{
		m_metadata_map.erase(*i);
	}
}

} // end namespace sysdig
