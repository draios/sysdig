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

#include <shared_object_cache.h>

namespace userspace_common
{

template<class TKey, class TValue>
void shared_object_cache<TKey, TValue>::insert(const TKey& key, const value_ptr_t& value)
{
	auto data = m_data.lock();
	(*data)[key] = value;
}

template<class TKey, class TValue>
bool shared_object_cache<TKey, TValue>::erase(const TKey& key)
{
	auto data = m_data.lock();
	return data->erase(key) > 0;
}

template<class TKey, class TValue>
typename shared_object_cache<TKey, TValue>::value_ptr_t shared_object_cache<TKey, TValue>::get(const TKey& key)
{
	auto data = m_data.lock();
	auto it = data->find(key);
	if(it != data->end())
	{
		return it->second;
	}

	return value_ptr_t(nullptr);
}

template<class TKey, class TValue>
typename shared_object_cache<TKey, TValue>::guard_t shared_object_cache<TKey, TValue>::lock()
{
	return m_data.lock();
}

}
