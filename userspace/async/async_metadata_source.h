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

#include <chrono>
#include <condition_variable>
#include <functional>
#include <list>
#include <map>
#include <mutex>
#include <thread>
#include <stdint.h>

namespace sysdig
{

/**
 * Base class for classes that need to collect metadata asynchronously from some
 * metadata source.  Subclasses will override the the run_impl() method.  In
 * that method, subclasses will use use dequeue_next_key() method to get the
 * key that it will use to collect the metadata, collect the appropriate
 * metadata, and call the store_metadata() method to save the metadata.  The
 * run_impl() method should continue to dequeue and process metadata while the
 * queue_size() method returns non-zero.
 *
 * The constructor for this class accepts a maximum wait time; this specifies
 * how long client code is willing to wait for a synchronous response (i.e.,
 * how long the lookup() method will block waiting for the requested metadata).
 * If the async_metadata_source is able to collect the requested metadata within
 * that time period, then the lookup() method will return them.
 *
 * If the lookup() method is unable to collect the requested metadata within
 * the requested time period, then one of two things will happen.  (1) If
 * the client supplied a handler in the call to lookup(), then that handler
 * will be invoked by the async_metadata_source once the metadata has been
 * collected.  Note that the callback handler will be invoked in the context
 * of the asynchronous thread associated with the async_metadata_source.  (2) If
 * the client did not supply a handler, then the metadata will be stored, and the
 * next call to the lookup() method with the same key will return the previously
 * collected metadata.
 *
 * @tparam key_type      The type of the keys for which concrete subclasses will
 *                       query.
 * @tparam metadata_type The type of metadata that concrete subclasses will
 *                       receive from a query.
 */
template<typename key_type, typename metadata_type>
class async_metadata_source
{
public:
	/**
	 * If provided to the constructor as max_wait_ms, then lookup will
	 * not wait for a response.
	 */
	const static uint64_t NO_LOOKUP_WAIT = 0;

        typedef std::function<void(const key_type& key,
			           const metadata_type& metadata)> callback_handler;

	/**
	 * Initialize this new async_metadata_source, which will block
	 * synchronously for the given max_wait_ms for metadata collection.
	 *
	 * @param[in] max_wait_ms The maximum amount of time that client code
	 *                        is willing to wait for lookup() to collect
	 *                        metadata before falling back to an async
	 *                        return.
	 * @param[in] ttl_ms      The time, in milliseconds, that a cached
	 *                        result will live before being considered
	 *                        "too old" and being pruned.
	 */
	async_metadata_source(uint64_t max_wait_ms, uint64_t ttl_ms);

	async_metadata_source(const async_metadata_source&) = delete;
	async_metadata_source(async_metadata_source&&) = delete;
	async_metadata_source& operator=(const async_metadata_source&) = delete;

	virtual ~async_metadata_source();

	/**
	 * Returns the maximum amount of time, in milliseconds, that a call to
	 * lookup() will block synchronously before returning.
	 */
	uint64_t get_max_wait() const;

	/**
	 * Returns the maximum amount of time, in milliseconds, that a cached
	 * metadata result will live before being pruned.
	 */
	uint64_t get_ttl() const;

	/**
	 * Lookup metadata based on the given key.  This method will block
	 * the caller for up the max_wait_ms time specified at construction
	 * for the desired metadata to be available.
	 *
	 * @param[in] key     The key to the metadata for which the client wishes
	 *                    to query.
	 * @param[out] metadata If this method is able to fetch the desired
	 *                    metadata within the max_wait_ms specified at
	 *                    construction time, then this output parameter will
	 *                    contain the collected metadata.  The value of this
	 *                    parameter is defined only if this method returns
	 *                    true.
	 * @param[in] handler If this method is unable to collect the requested
	 *                    metadata before the timeout, and if this parameter
	 *                    is a valid, non-empty, function, then this class
	 *                    will invoke the given handler from the async
	 *                    thread immediately after the collected metadata
	 *                    are available.  If this handler is empty, then
	 *                    this async_metadata_source will store the metadata
	 *                    and return them on the next call to lookup().
	 *
	 * @returns true if this method was able to lookup and return the
	 *          metadata synchronously; false otherwise.
	 */
	bool lookup(const key_type& key,
                    metadata_type& metadata,
                    const callback_handler& handler = callback_handler());

	/**
	 * @returns true if the async thread assocaited with this
	 *          async_metadata_source is running, false otherwise.
	 */
	bool is_running() const;

protected:
	/**
	 * Stops the thread assocaited with this async_metadata_source, if
	 * it is running.
	 */
	void stop();

	/**
	 * Returns the number of elements in the requeust queue.  Concrete
	 * subclasses will call this methods from their run_impl() methods to
	 * determine if there is more asynchronous work from them to perform.
	 *
	 * @returns the size of the request queue.
	 */
	std::size_t queue_size() const;

	/**
	 * Dequeues an entry from the request queue and returns it.  Concrete
	 * subclasses will call this method to get the next key for which
	 * to collect metadata.
	 *
	 * Precondition: queue_size() must be non-zero.
	 *
	 * @returns the next key to look up.
	 */
	key_type dequeue_next_key();

	metadata_type get_metadata(const key_type& key);

	/**
	 * Stores a collected set of metadata for the given key.  Concrete
	 * subclasses will call this method from their run_impl() method to
	 * save (or otherwise notifiy the client about) a collected metadata.
	 *
	 * @param[in] key      The key for which the client asked for metadata.
	 * @param[in] metadata The collected metadata.
	 */
	void store_metadata(const key_type& key, const metadata_type& metadata);

	/**
	 * Concrete subclasses must override this method to perform the
	 * asynchronous metadata lookup.
	 */
	virtual void run_impl() = 0;

private:
	struct lookup_request
	{
		lookup_request():
			m_available(false),
			m_metadata(),
			m_available_condition(),
			m_callback(),
			m_start_time(std::chrono::steady_clock::now())
		{ }

		bool m_available;
		metadata_type m_metadata;
		std::condition_variable m_available_condition;
		callback_handler m_callback; // TODO: This may need to be a list
		std::chrono::time_point<std::chrono::steady_clock> m_start_time;
	};

	typedef std::map<key_type, lookup_request> metadata_map;

	void run();
	void prune_stale_requests();

	uint64_t m_max_wait_ms;
	uint64_t m_ttl_ms;
	std::thread m_thread;
	bool m_running;
	bool m_terminate;
	mutable std::mutex m_mutex;
	std::condition_variable m_start_condition;
	std::condition_variable m_queue_not_empty_condition;
	std::list<key_type> m_request_queue;
	metadata_map m_metadata_map;
};


} // end namespace sysdig

#include "async_metadata_source.tpp"
