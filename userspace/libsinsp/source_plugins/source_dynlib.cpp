#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <sinsp.h>
#include "source_plugin.h"
#ifndef _WIN32
#include <dlfcn.h>
#include <inttypes.h>
#endif


static void* getsym(void* handle, const char* name)
{
#ifdef _WIN32
	return GetProcAddress((HINSTANCE)handle, name);
#else
	return dlsym(handle, name);
#endif
}

bool create_dynlib_source(string libname, OUT source_plugin_info* info, OUT string* error)
{
#ifdef _WIN32
	HINSTANCE handle = LoadLibrary(libname.c_str());
#else
	void* handle = dlopen(libname.c_str(), RTLD_LAZY);
#endif
	if(handle == NULL)
	{
		*error = "error loading plugin " + libname + ": " + strerror(errno);
		return false;
	}

	*(void**)(&(info->init)) = getsym(handle, "plugin_init");
	*(void**)(&(info->destroy)) = getsym(handle, "plugin_destroy");
	*(void**)(&(info->get_last_error)) = getsym(handle, "plugin_get_last_error");
	*(void**)(&(info->get_type)) = getsym(handle, "plugin_get_type");
	*(void**)(&(info->get_id)) = getsym(handle, "plugin_get_id");
	*(void**)(&(info->get_name)) = getsym(handle, "plugin_get_name");
	*(void**)(&(info->get_description)) = getsym(handle, "plugin_get_description");
	*(void**)(&(info->get_fields)) = getsym(handle, "plugin_get_fields");
	*(void**)(&(info->open)) = getsym(handle, "plugin_open");
	*(void**)(&(info->close)) = getsym(handle, "plugin_close");
	*(void**)(&(info->next)) = getsym(handle, "plugin_next");
	*(void**)(&(info->event_to_string)) = getsym(handle, "plugin_event_to_string");
	*(void**)(&(info->extract_str)) = getsym(handle, "plugin_extract_str");

	return true;
}
