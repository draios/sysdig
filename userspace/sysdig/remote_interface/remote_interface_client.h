/*
Copyright (C) 2022 Sysdig Inc.

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

// This interface represents the client shim that is *always* linked
// into the sysdig/falco/logwolf executable. It dlopen()s a shared
// library and calls C functions to extend functionality to the code
// in the shared library.

#include <string>
#include <list>

#include "remote_interface_types.h"

class remote_interface_client {
public:
	remote_interface_client();
	virtual ~remote_interface_client();

	// Open the shared library at path, which provides the
	// extended functionality.
	bool init(const std::string &path, std::string &errstr);

	// Return a list of available "remote interfaces" that can be
	// opened.
	bool list_ifaces(std::list<remote_interface> &ifaces, std::string &errstr);

	// Open the interface with the provided name. What is returned
	// is a path to a capture file that can be opened like any other
	// capture file.
	bool open_iface(const std::string &iface_name, std::string &path, std::string &errstr);

	// Close the interface with the provided name.
	bool close_iface(const std::string &iface_name, std::string &errstr);

private:

	// Look up the function with the provided name and return a
	// function pointer to it.
	void *getsym(const char *name, std::string &errstr);

	remote_interface_handle m_handle;
};

