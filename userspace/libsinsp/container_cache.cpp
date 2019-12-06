
#include "container_cache.h"

namespace libsinsp
{

//static
container_cache container_cache::m_instance;

}

// explicit instantiation of base class
#include <shared_object_cache.hpp>
template class userspace_common::shared_object_cache<std::string, sinsp_container_info>;
