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

template<class TKey, class TValue>
class shared_object_cache
{
public:
	using value_ptr_t = std::shared_ptr<const TValue>;
	using map_t = std::unordered_map<TKey, value_ptr_t>;

	void insert(const TKey& key, const value_ptr_t& value);

	bool erase(const TKey& key);

	value_ptr_t get(const TKey& value);

	using guard_t = MutexGuard<map_t>;
	guard_t lock();


private:
	userspace_common::Mutex<map_t> m_data;
};

}
