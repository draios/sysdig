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

#include <gtest.h>
#include "shared_object_cache.hpp"

using namespace userspace_common;

namespace {

/**
 * This struct has stuff in it.
 */
struct stuff
{
	using ptr = std::shared_ptr<const stuff>;

	stuff() :
	   a(0),
	   b(0),
	   c(0)
	{ }

	~stuff()
	{
		a = 0xdeadbeef;
		b = 0xdeadbeef;
		c = 0xdeadbeef;
	}

	stuff(int a_val, int b_val, int c_val) :
	   a(a_val),
	   b(b_val),
	   c(c_val)
	{ }

	int a;
	int b;
	int c;

	bool operator==(const stuff& rhs) const
	{
		return a == rhs.a && b == rhs.b && c == rhs.c;
	}

};
using stuff_cache = shared_object_cache<std::string, stuff>;

} // anonymous namespace

// Ensure basic functionality of the class, namely that you can read what you
// write.
TEST(shared_object_cache_test, insert_read_erase)
{
	stuff_cache some_stuff;
	std::string key("key");

	stuff my_stuff(1, 2, 3);

	{
		stuff::ptr my_stuff_copy = std::make_shared<stuff>(my_stuff);
		some_stuff.insert_or_assign(key, my_stuff_copy);
	}

	auto found = some_stuff.get(key);
	ASSERT_EQ(my_stuff, *found);

	bool erased = some_stuff.erase(key);
	ASSERT_TRUE(erased);

	auto not_found = some_stuff.get(key);
	ASSERT_EQ(nullptr, not_found.get());

	// Validate the found value again to make sure it wasn't destroyed
	ASSERT_EQ(my_stuff, *found);
}

// Ensure that replace will keep the newer one
TEST(shared_object_cache_test, replace)
{
	stuff_cache some_stuff;
	std::string key("key");

	stuff my_stuff(1, 2, 3);
	some_stuff.insert_or_assign(key, std::make_shared<stuff>(10, 20, 30));
	some_stuff.insert_or_assign(key, std::make_shared<stuff>(my_stuff));

	auto found = some_stuff.get(key);
	ASSERT_EQ (my_stuff, *found);
}
