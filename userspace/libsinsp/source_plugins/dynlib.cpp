#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <sinsp.h>
#include "source_plugin.h"
#ifndef _WIN32
#include <dlfcn.h>
#include <inttypes.h>
#endif


//
// Plugin method types defintions
//
typedef src_plugin_t* (*init_t)(char* config, int32_t* rc);
typedef char* (*get_last_error_t)();
typedef void (*destroy_t)(src_plugin_t* s);
typedef uint32_t (*get_id_t)();
typedef char* (*get_name_t)();
typedef char* (*get_description_t)();
typedef char* (*get_fields_t)();
typedef src_instance_t* (*open_t)(src_plugin_t* s, int32_t* rc);
typedef void (*close_t)(src_plugin_t* s, src_instance_t* h);
typedef int32_t (*next_t)(src_plugin_t* s, src_instance_t* h, uint8_t** data, uint32_t* datalen);
typedef char* (*event_to_string_t)(uint8_t* data, uint32_t datalen);
typedef char* (*extract_as_string_t)(uint64_t evtnum, uint32_t id, char* arg, uint8_t* data, uint32_t datalen);

bool create_dynlib_source(string libname, OUT source_plugin_info* info, OUT string* error)
{
#ifndef _WIN32
	void* handle = dlopen(libname.c_str(), RTLD_LAZY);

	if(handle == NULL)
	{
		*error = "error loading plugin " + libname + ": " + strerror(errno);
		return false;
	}

	init_t pinit;
	*(void**)(&pinit) = dlsym(handle, "plugin_init");
	if(pinit == NULL)
	{
		*error = "plugin " + libname + " is not exporting the plugin_init() function";
		return false;
	}

	get_last_error_t pget_last_error;
	*(void**)(&pget_last_error) = dlsym(handle, "plugin_get_last_error");
	if(pget_last_error == NULL)
	{
		*error = "plugin " + libname + " is not exporting the plugin_get_last_error() function";
		return false;
	}

	destroy_t pdestroy;
	*(void**)(&pdestroy) = dlsym(handle, "plugin_destroy");
	if(pdestroy == NULL)
	{
		*error = "plugin " + libname + " is not exporting the plugin_destroy() function";
		return false;
	}

	get_id_t pget_id;
	*(void**)(&pget_id) = dlsym(handle, "plugin_get_id");
	if(pget_id == NULL)
	{
		*error = "plugin " + libname + " is not exporting the plugin_get_id() function";
		return false;
	}

	get_name_t pget_name;
	*(void**)(&pget_name) = dlsym(handle, "plugin_get_name");
	if(pget_name == NULL)
	{
		*error = "plugin " + libname + " is not exporting the plugin_get_name() function";
		return false;
	}

	get_description_t pget_description;
	*(void**)(&pget_description) = dlsym(handle, "plugin_get_description");
	if(pget_description == NULL)
	{
		*error = "plugin " + libname + " is not exporting the plugin_get_description() function";
		return false;
	}

	get_fields_t pget_fields;
	*(void**)(&pget_fields) = dlsym(handle, "plugin_get_fields");
	if(pget_fields == NULL)
	{
		*error = "plugin " + libname + " is not exporting the plugin_get_fields() function";
		return false;
	}

	open_t popen;
	*(void**)(&popen) = dlsym(handle, "plugin_open");
	if(popen == NULL)
	{
		*error = "plugin " + libname + " is not exporting the plugin_open() function";
		return false;
	}

	close_t pclose;
	*(void**)(&pclose) = dlsym(handle, "plugin_close");
	if(pclose == NULL)
	{
		*error = "plugin " + libname + " is not exporting the plugin_close() function";
		return false;
	}

	next_t pnext;
	*(void**)(&pnext) = dlsym(handle, "plugin_next");
	if(pnext == NULL)
	{
		*error = "plugin " + libname + " is not exporting the plugin_next() function";
		return false;
	}

	event_to_string_t pevent_to_string;
	*(void**)(&pevent_to_string) = dlsym(handle, "plugin_event_to_string");
	if(pevent_to_string == NULL)
	{
		*error = "plugin " + libname + " is not exporting the plugin_event_to_string() function";
		return false;
	}

	extract_as_string_t pextract_as_string;
	*(void**)(&pextract_as_string) = dlsym(handle, "plugin_extract_as_string");
	if(pextract_as_string == NULL)
	{
		*error = "plugin " + libname + " is not exporting the plugin_extract_as_string() function";
		return false;
	}
#else // _WIN32
	HINSTANCE pdll = LoadLibrary(libname.c_str());
	if(pdll == NULL)
	{
		*error = "error loading plugin " + libname + ": " + to_string(GetLastError());
		return false;
	}

	init_t pinit;
	*(void**)(&pinit) = GetProcAddress(pdll, "plugin_init");
	if(pinit == NULL)
	{
		*error = "plugin " + libname + " is not exporting the plugin_init() function";
		return false;
	}

	get_last_error_t pget_last_error;
	*(void**)(&pget_last_error) = GetProcAddress(pdll, "plugin_get_last_error");
	if(pget_last_error == NULL)
	{
		*error = "plugin " + libname + " is not exporting the plugin_get_last_error() function";
		return false;
	}

	destroy_t pdestroy;
	*(void**)(&pdestroy) = GetProcAddress(pdll, "plugin_destroy");
	if(pdestroy == NULL)
	{
		*error = "plugin " + libname + " is not exporting the plugin_destroy() function";
		return false;
	}

	get_id_t pget_id;
	*(void**)(&pget_id) = GetProcAddress(pdll, "plugin_get_id");
	if(pget_id == NULL)
	{
		*error = "plugin " + libname + " is not exporting the plugin_get_id() function";
		return false;
	}

	get_name_t pget_name;
	*(void**)(&pget_name) = GetProcAddress(pdll, "plugin_get_name");
	if(pget_name == NULL)
	{
		*error = "plugin " + libname + " is not exporting the plugin_get_name() function";
		return false;
	}

	get_description_t pget_description;
	*(void**)(&pget_description) = GetProcAddress(pdll, "plugin_get_description");
	if(pget_description == NULL)
	{
		*error = "plugin " + libname + " is not exporting the plugin_get_description() function";
		return false;
	}

	get_fields_t pget_fields;
	*(void**)(&pget_fields) = GetProcAddress(pdll, "plugin_get_fields");
	if(pget_fields == NULL)
	{
		*error = "plugin " + libname + " is not exporting the plugin_get_fields() function";
		return false;
	}

	open_t popen;
	*(void**)(&popen) = GetProcAddress(pdll, "plugin_open");
	if(popen == NULL)
	{
		*error = "plugin " + libname + " is not exporting the plugin_open() function";
		return false;
	}

	close_t pclose;
	*(void**)(&pclose) = GetProcAddress(pdll, "plugin_close");
	if(pclose == NULL)
	{
		*error = "plugin " + libname + " is not exporting the plugin_close() function";
		return false;
	}

	next_t pnext;
	*(void**)(&pnext) = GetProcAddress(pdll, "plugin_next");
	if(pnext == NULL)
	{
		*error = "plugin " + libname + " is not exporting the plugin_next() function";
		return false;
	}

	event_to_string_t pevent_to_string;
	*(void**)(&pevent_to_string) = GetProcAddress(pdll, "plugin_event_to_string");
	if(pevent_to_string == NULL)
	{
		*error = "plugin " + libname + " is not exporting the plugin_event_to_string() function";
		return false;
	}

	extract_as_string_t pextract_as_string;
	*(void**)(&pextract_as_string) = GetProcAddress(pdll, "plugin_extract_as_string");
	if(pextract_as_string == NULL)
	{
		*error = "plugin " + libname + " is not exporting the plugin_extract_as_string() function";
		return false;
	}
#endif // _WIN32

	info->init = pinit;
	info->get_last_error = pget_last_error;
	info->destroy = pdestroy;
	info->get_id = pget_id;
	info->get_name = pget_name;
	info->get_description = pget_description;
	info->get_fields = pget_fields;
	info->open = popen;
	info->close = pclose;
	info->next = pnext;
	info->event_to_string = pevent_to_string;
	info->extract_as_string = pextract_as_string;

	return true;
}
