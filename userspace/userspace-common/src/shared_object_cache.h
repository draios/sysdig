/*
Copyright (C) 2019 Sysdig Inc.

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

#include <cstddef>
#include <memory>
#include <unordered_map>
#include "mutex.h"

namespace userspace_common
{

/**
 * Cache of smart pointers to const objects.
 *
 * The public API of this class is (mostly) thread-safe. The cache is locked
 * while the underlying map is modified or searched. To retrieve a value,
 * the shared_ptr is copied under lock and then the shared_ptr is returned.
 * Since the shared_ptr points to a const object, that object can be read by
 * multiple threads regardless of whether the map is locked or whether the
 * object stays in the map.
 *
 * If a value needs to be modified, then a new object should be created and
 * inserted with the same key.
 */
template<class TKey, class TValue>
class shared_object_cache
{
public:
	using value_ptr_t = std::shared_ptr<const TValue>;
	using map_t = std::unordered_map<TKey, value_ptr_t>;

	/**
	 * Insert (or replace) into the map with the given key and value.
	 */
	void insert(const TKey& key, const value_ptr_t& value);

	/**
	 * Erase the element with the given key.
	 */
	bool erase(const TKey& key);

	/**
	 * Return a shared_ptr to a const object in the map.
	 */
	value_ptr_t get(const TKey& value) const;

	using guard_t = ConstMutexGuard<map_t>;
	using mutable_guard_t = MutexGuard<map_t>;

	/**
	 * Lock and provide const access to the underlying map. The map will remain
	 * locked as long as the guard exists.
	 */
	guard_t lock() const;

	/**
	 * Lock and provide mutable access to the underlying map. The map will
	 * remain locked as long as the guard exists.
	 *
	 * This function gives full writable access to the map so it can break
	 * thread-safety. It should be used carefully.
	 */
	mutable_guard_t mutable_lock();

private:
	userspace_common::Mutex<map_t> m_data;
};

}
