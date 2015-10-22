//
// k8s_common.h
//

#pragma once

//
// Macros for enable/disable k8s threading
// Used to eliminate mutex locking when running single-threaded
//

#ifndef K8S_DISABLE_THREAD
#include <mutex>
#define K8S_DECLARE_MUTEX mutable std::mutex m_mutex
#define K8S_LOCK_GUARD_MUTEX std::lock_guard<std::mutex> lock(m_mutex)
#else
#define K8S_DECLARE_MUTEX
#define K8S_LOCK_GUARD_MUTEX
#endif // K8S_DISABLE_THREAD
