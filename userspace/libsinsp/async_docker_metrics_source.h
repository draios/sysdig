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

#include "async_metric_source.h"
#include "sinsp.h"
#include "container.h"

namespace sysdig
{

// TODO: Can this be inside the class below?
struct docker_metrics
{
	docker_metrics():
		m_manager(nullptr),
		m_container_info()
	{
	}

	docker_metrics(sinsp_container_manager* const manager,
	               std::shared_ptr<sinsp_container_info>& container_info):
		m_manager(manager),
		m_container_info(container_info)
	{
	}


	sinsp_container_manager* m_manager;
	std::shared_ptr<sinsp_container_info> m_container_info;
};

/**
 * Interface to async_docker_metrics_source -- an abstract async_metric_source
 * for fetching docker metrics and metadata.
 */
class async_docker_metrics_source : public async_metric_source<std::string, docker_metrics>
{
public:
	/** The default port on which Docker listens for REST requests. */
	static const uint16_t DEFAULT_PORT;

	/**
	 * Returns the API version that this async_metric_source will use to
	 * fetch information from Docker.
	 */
	const std::string& get_api_version() const;


	/**
	 * Returns the port that this async_docker_metrics_source will use
	 * to connect to Docker.
	 */
	uint16_t get_port() const;

	/**
	 * Returns true if this async_docker_metrics_source should query for
	 * image info, false otherwise.
	 */
	bool query_image_info() const;

	/**
	 * Update the query_image_info state for this async_docker_metrics_source.
	 */
	void set_query_image_info(bool query_info);

	/**
	 * Creates a new async_docker_metric_source that is appropriate
	 * for the build environment (Linux/Windows/no-analyzer)
	 *
	 * Note that the caller is responsible for deleting the returned object.
	 */
	static async_docker_metrics_source* new_async_docker_metrics_source();

protected:
	async_docker_metrics_source(const std::string& api_version,
	                            uint16_t port = DEFAULT_PORT);

	/**
	 * Builds and returns a URL for querying Docker on the local host.
	 * This differs between Linux and Windows, so the concrete implementation
	 * is left to subclasses.
	 *
	 * @param[in] url The base path of the URL
	 */
	virtual std::string build_request(const std::string& url) = 0;

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
	 * this async_docker_metrics_source.
	 */
	void run_impl() override;

private:
	bool m_query_image_info;
	std::string m_api_version;
	uint16_t m_port;
};

} // end namespace sysdig
