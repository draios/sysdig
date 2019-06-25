/*
Copyright (C) 2019 Draios Inc dba Sysdig.

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

#include "async_key_value_source.h"
#include "container_info.h"
#include "container.h"

namespace sysdig {
/**
 * \brief Base class for async container metadata sources
 * @tparam key_type lookup key (container id plus optionally other data)
 *
 * The result type is hardcoded as sinsp_container_info.
 */
template<typename key_type>
class async_container_source : public async_key_value_source<key_type, sinsp_container_info>
{
public:
	using async_key_value_source<key_type, sinsp_container_info>::async_key_value_source;

	/**
	 * \brief Start async lookup of container metadata
	 * @param key the container lookup key
	 * @param manager the instance of sinsp_container_manager to store
	 * the metadata found
	 */
	void lookup_container(const key_type& key, sinsp_container_manager *manager);

	/**
	 * \brief Wait for all pending lookups to complete
	 */
	void quiesce() {
		this->stop();
	}
};

template<typename key_type>
void async_container_source<key_type>::lookup_container(const key_type& key, sinsp_container_manager *manager)
{
	auto cb = [manager](const key_type& key, const sinsp_container_info &res)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"async_container_source (%s): Source callback result successful=%s",
				static_cast<const std::string&>(key).c_str(),
				(res.m_successful ? "true" : "false"));

		// store the container metadata in container_manager regardless of the result
		// this ensures that we don't get stuck with incomplete containers
		// when all async lookups fail
		//
		// the manager will ignore any lookup results reported after the first
		// successful one and return false
		//
		// if we did use the metadata and the lookup succeeded,
		// generate a container event for libsinsp consumers
		if(manager->update_container(res) && res.m_successful)
		{
			manager->notify_new_container(res);
		}
	};

	sinsp_container_info result;

	if (this->lookup(key, result, cb))
	{
		// if a previous lookup call already found the metadata, process it now
		cb(key, result);

		// This should *never* happen, as ttl is 0 (never wait)
		g_logger.format(sinsp_logger::SEV_ERROR,
				"async_container_source (%s): Unexpected immediate return from lookup()",
				static_cast<const std::string&>(key).c_str());
	}

}
}
