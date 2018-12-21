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
 * Base class for classes that need to collect metrics asynchronously from some
 * metric source.  Subclasses will override the the run_impl() method.  In
 * that method, subclasses will use use dequeue_next_key() method to get the
 * key that it will use to collect the metrics, collect the appropriate metrics,
 * and call the store_metrics() method to save the metrics.  The run_impl()
 * method should continue to dequeue and process metrics while the queue_size()
 * method returns non-zero.
 *
 * The constructor for this class accepts a maximum wait time; this specifies
 * how long client code is willing to wait for a synchronous response (i.e.,
 * how long the lookup() method will block waiting for the requested metrics).
 * If the async_metric_source is able to collect the requested metrics within
 * that time period, then the lookup() method will return them.
 *
 * If the lookup() method is unable to collect the requested metrics within
 * the requested time period, then one of two things will happen.  (1) If
 * the client supplied a handler in the call to lookup(), then that handler
 * will be invoked by the async_metric_source once the metric has been
 * collected.  Note that the callback handler will be invoked in the context
 * of the asynchronous thread associated with the async_metric_source.  (2) If
 * the client did not supply a handler, then the metric will be stored, and the
 * next call to the lookup() method with the same key will return the previously
 * collected metrics.
 *
 * @tparam key_type    The type of the keys for which concrete subclasses will
 *                     query.
 * @tparam metric_type The type of metric that concrete subclasses will receive
 *                     from a query.
 */
template<typename key_type, typename metric_type>
class async_metric_source
{
public:
        typedef std::function<void(const key_type& key,
			           const metric_type& metric)> callback_handler;

	/**
	 * Initialize this new async_metric_source, which will block
	 * synchronously for the given max_wait_ms for metric collection.
	 *
	 * @param[in] max_wait_ms The maximum amount of time that client code
	 *                        is willing to wait for lookup() to collect
	 *                        metrics before falling back to an async
	 *                        return.
	 */
	async_metric_source(uint64_t max_wait_ms);

	async_metric_source(const async_metric_source&) = delete;
	async_metric_source(async_metric_source&&) = delete;
	async_metric_source& operator=(const async_metric_source&) = delete;

	virtual ~async_metric_source();

	uint64_t get_max_wait() const;

	/**
	 * Lookup metrics based on the given key.  This method will block
	 * the caller for up the max_wait_ms time specified at construction
	 * for the desired metrics to be available.
	 *
	 * @param[in] key     The key to the metric for which the client wishes
	 *                    to query.
	 * @param[out] metric If this method is able to fetch the desired
	 *                    metrics within the max_wait_ms specified at
	 *                    construction time, then this output parameter will
	 *                    contain the collected metrics.  The value of this
	 *                    parameter is defined only if this method returns
	 *                    true.
	 * @param[in] handler If this method is unable to collect the requested
	 *                    metrics before the timeout, and if this parameter
	 *                    is a valid, non-empty, function, then this class
	 *                    will invoke the given handler from the async
	 *                    thread immediately after the collected metrics
	 *                    are available.  If this handler is empty, then
	 *                    this async_metric_source will store the metrics
	 *                    and return them on the next call to lookup().
	 *
	 * @returns true if this method was able to lookup and return the
	 *          metric synchronously; false otherwise.
	 */
	bool lookup(const key_type& key,
                    metric_type& metric,
                    const callback_handler& handler = callback_handler());

	/**
	 * @returns true if the async thread assocaited with this
	 *          async_metric_source is running, false otherwise.
	 */
	bool is_running() const;

protected:
	/**
	 * Stops the thread assocaited with this async_metric_source, if
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
	 * to collect metrics.
	 *
	 * Precondition: queue_size() must be non-zero.
	 *
	 * @returns the next key to look up.
	 */
	key_type dequeue_next_key();

	/**
	 * Stores a collected set of metrics for the given key.  Concrete
	 * subclasses will call this method from their run_impl() method to
	 * save (or otherwise notifiy the client about) a collected metric.
	 *
	 * @param[in] key     The key for which the client asked for metrics.
	 * @param[in] metrics The collected metrics.
	 */
	void store_metric(const key_type& key, const metric_type& metric);

	/**
	 * Concrete subclasses must override this method to perform the
	 * asynchronous metric lookup.
	 */
	virtual void run_impl() = 0;

private:
	struct lookup_request
	{
		lookup_request():
			m_available(false),
			m_metric(),
			m_available_condition(),
			m_callback()
		{}

		bool m_available;
		metric_type m_metric;
		std::condition_variable m_available_condition;
		callback_handler m_callback; // TODO: This may need to be a list
	};

	typedef std::map<key_type, lookup_request> metric_map;

	void run();

	uint64_t m_max_wait_ms;
	std::thread m_thread;
	bool m_running;
	bool m_terminate;
	mutable std::mutex m_mutex;
	std::condition_variable m_start_condition;
	std::condition_variable m_queue_not_empty_condition;
	std::list<key_type> m_request_queue;
	metric_map m_metric_map;
};


} // end namespace sysdig

#include "async_metric_source.tpp"
