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

#include <dlfcn.h>

#include "remote_interface_client.h"

remote_interface_client::remote_interface_client()
	: m_handle(NULL)
{
}

remote_interface_client::~remote_interface_client()
{
}

bool remote_interface_client::init(const std::string &path, std::string &errstr)
{
#ifdef _WIN32
	m_handle = (HINSTANCE)GetModuleHandle(path.c_str());
#else
	m_handle = dlopen(path.c_str(), RTLD_LAZY);
#endif

	if(m_handle == NULL)
	{
		errstr = "error loading extension " + path + ": " + dlerror();
		return false;
	}

	const char * (*get_api_version)();
	*(void **) (&get_api_version) = getsym("get_api_version", errstr);

	if(get_api_version == NULL)
	{
		return false;
	}

	std::string version = get_api_version();

	// Perform version checks here
	errstr = "";
	return true;
}

bool remote_interface_client::list_ifaces(std::list<remote_interface> &ifaces, std::string &errstr)
{
	bool (*list_ifaces)(std::list<remote_interface> &, std::string &);
	*(void **) (&list_ifaces) = getsym("list_ifaces", errstr);

	if(list_ifaces == NULL)
	{
		return false;
	}

	return list_ifaces(ifaces, errstr);
}

bool remote_interface_client::open_iface(const std::string &iface_name, const std::string &filter,
					 std::string &path, std::string &errstr)
{
	bool (*open_iface)(const std::string &, const std::string &, std::string &, std::string &);
	*(void **)(&open_iface) = getsym("open_iface", errstr);

	if(open_iface == NULL)
	{
		return false;
	}

	return open_iface(iface_name, filter, path, errstr);
}

bool remote_interface_client::close_iface(const std::string &iface_name, std::string &errstr)
{
	bool (*close_iface)(const std::string &, std::string &);
	*(void **) (&close_iface) = getsym("close_iface", errstr);

	if(close_iface == NULL)
	{
		return false;
	}

	return close_iface(iface_name, errstr);
}

void *remote_interface_client::getsym(const char *name, std::string &errstr)
{
	void *ret;

#ifdef _WIN32
	ret = GetProcAddress(m_handle, name);
#else
	ret = dlsym(m_handle, name);
#endif

	if(ret == NULL)
	{
		errstr = std::string("Dynamic library symbol ") + name + " not present";
	} else {
		errstr = "";
	}

	return ret;
}
