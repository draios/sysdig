#pragma once

#include <shared_object_cache.h>
#include "container_info.h"

namespace libsinsp
{
/**
 * Cache of container_info.
 */
class container_cache : public userspace_common::shared_object_cache<std::string, sinsp_container_info>
{
public:
	static container_cache &instance()
	{
		return m_instance;
	}

private:

	static container_cache m_instance;
};

} // namespace libsinsp
