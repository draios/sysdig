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

#include "async_key_value_source.h"
#include "sinsp.h"
#include "container.h"

namespace sysdig
{

/**
 * The value_type that an async_docker_metadata_source's lookup() method
 * will produce.
 */
struct docker_metadata
{
	docker_metadata():
		m_manager(nullptr),
		m_container_info()
	{ }

	docker_metadata(sinsp_container_manager* const manager,
	               std::shared_ptr<sinsp_container_info>& container_info):
		m_manager(manager),
		m_container_info(container_info)
	{ }

	sinsp_container_manager* m_manager;
	std::shared_ptr<sinsp_container_info> m_container_info;
};

/**
 * Interface to async_docker_metadata_source -- an abstract async_key_value_source
 * for fetching docker metadata and metadata.
 */
class async_docker_metadata_source : public async_key_value_source<std::string,
	                                                           docker_metadata>
{
public:
	/**
	 * The maximum amount of time that a collected Docker metric will
	 * remain cached waiting for a subsequent call to lookup() before
	 * being discarded.
	 */
	const uint64_t MAX_TTL_MS = (30 * 1000);

	/**
	 * Returns the API version that this async_key_value_source will use to
	 * fetch information from Docker.
	 */
	const std::string& get_api_version() const;

	/**
	 * Returns true if this async_docker_metadata_source should query for
	 * image info, false otherwise.
	 */
	bool query_image_info() const;

	/**
	 * Update the query_image_info state for this async_docker_metadata_source.
	 */
	void set_query_image_info(bool query_info);

	/**
	 * Creates a new async_docker_metadata_source that is appropriate
	 * for the build environment (Linux/Windows/no-analyzer)
	 *
	 * @param[in] query_image_info If image information is missing, should
	 *                             we query Docker for it?
	 *
	 * Note that the caller is responsible for deleting the returned object.
	 */
	static async_docker_metadata_source* new_async_docker_metadata_source(
			bool query_image_info);

protected:
	/**
	 * Initialize a new async_docker_metadata_source.
	 *
	 * @param[in] api_version      The version of the Docker API to use.
	 * @param[in] query_image_info Should this componenty query Docker for
	 *                             missing image information?
	 */
	async_docker_metadata_source(const std::string& api_version,
	                             bool query_image_info = true);

	/**
	 * Builds and returns a URL for querying Docker on the local host.
	 * This differs between Linux and Windows, so the concrete implementation
	 * is left to subclasses.
	 *
	 * @param[in] path The base path of the URL
	 */
	virtual std::string build_request(const std::string& path) = 0;

	/**
	 * Fetches the JSON from Docker using the given url.
	 *
	 * @param[in]  manager Used to query container information
	 * @param[in]  url     The URL to query
	 * @param[out] json    The fetched JSON
	 */
	virtual sinsp_docker_response get_docker(sinsp_container_manager* manager,
	                                         const std::string& url,
	                                         std::string &json) = 0;

	/**
	 * Parses the JSON returned from Dcoker and populates the given
	 * container with the information within.
	 *
	 * @param[in]     manager   Used to query container information
	 * @param[in,out] container The container information to populate
	 *
	 * @returns true on success, false otherwise.
	 */
	bool parse_docker(sinsp_container_manager* manager,
                          sinsp_container_info *container);

	/**
	 * Drives the asynchronous fetching of the information from docker.
	 * This method runs in the context of the thread associated with
	 * this async_docker_metadata_source.
	 */
	void run_impl() override;

private:
	bool m_query_image_info;
	std::string m_api_version;
};

} // end namespace sysdig
