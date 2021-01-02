#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <sinsp.h>
#include "source_plugin.h"
#include <dlfcn.h>
#include <inttypes.h>

#define SO_NAME "./libcloudtrail_file.so"

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
typedef char* (*extract_as_string_t)(uint32_t id, uint8_t* data, uint32_t datalen);

source_plugin_info create_dynlib_source()
{
	void* handle = dlopen(SO_NAME, RTLD_LAZY);

	if(handle == NULL)
	{
		throw sinsp_exception(string("error loading plugin ") + SO_NAME + ": " + strerror(errno));
	}

	init_t pinit;
	*(void**)(&pinit) = dlsym(handle, "plugin_init");
	if(pinit == NULL)
	{
		throw sinsp_exception(string("plugin ") + SO_NAME + " is not exporting the plugin_init() function");
	}

	get_last_error_t pget_last_error;
	*(void**)(&pget_last_error) = dlsym(handle, "plugin_get_last_error");
	if(pget_last_error == NULL)
	{
		throw sinsp_exception(string("plugin ") + SO_NAME + " is not exporting the plugin_get_last_error() function");
	}

	destroy_t pdestroy;
	*(void**)(&pdestroy) = dlsym(handle, "plugin_destroy");
	if(pdestroy == NULL)
	{
		throw sinsp_exception(string("plugin ") + SO_NAME + " is not exporting the plugin_destroy() function");
	}

	get_id_t pget_id;
	*(void**)(&pget_id) = dlsym(handle, "plugin_get_id");
	if(pget_id == NULL)
	{
		throw sinsp_exception(string("plugin ") + SO_NAME + " is not exporting the plugin_get_id() function");
	}

	get_name_t pget_name;
	*(void**)(&pget_name) = dlsym(handle, "plugin_get_name");
	if(pget_name == NULL)
	{
		throw sinsp_exception(string("plugin ") + SO_NAME + " is not exporting the plugin_get_name() function");
	}

	get_description_t pget_description;
	*(void**)(&pget_description) = dlsym(handle, "plugin_get_description");
	if(pget_description == NULL)
	{
		throw sinsp_exception(string("plugin ") + SO_NAME + " is not exporting the plugin_get_description() function");
	}

	get_fields_t pget_fields;
	*(void**)(&pget_fields) = dlsym(handle, "plugin_get_fields");
	if(pget_fields == NULL)
	{
		throw sinsp_exception(string("plugin ") + SO_NAME + " is not exporting the plugin_get_fields() function");
	}

	open_t popen;
	*(void**)(&popen) = dlsym(handle, "plugin_open");
	if(popen == NULL)
	{
		throw sinsp_exception(string("plugin ") + SO_NAME + " is not exporting the plugin_open() function");
	}

	close_t pclose;
	*(void**)(&pclose) = dlsym(handle, "plugin_close");
	if(pclose == NULL)
	{
		throw sinsp_exception(string("plugin ") + SO_NAME + " is not exporting the plugin_close() function");
	}

	next_t pnext;
	*(void**)(&pnext) = dlsym(handle, "plugin_next");
	if(pnext == NULL)
	{
		throw sinsp_exception(string("plugin ") + SO_NAME + " is not exporting the plugin_next() function");
	}

	event_to_string_t pevent_to_string;
	*(void**)(&pevent_to_string) = dlsym(handle, "plugin_event_to_string");
	if(pevent_to_string == NULL)
	{
		throw sinsp_exception(string("plugin ") + SO_NAME + " is not exporting the plugin_event_to_string() function");
	}

	extract_as_string_t pextract_as_string;
	*(void**)(&pextract_as_string) = dlsym(handle, "plugin_extract_as_string");
	if(pextract_as_string == NULL)
	{
		throw sinsp_exception(string("plugin ") + SO_NAME + " is not exporting the plugin_extract_as_string() function");
	}

	source_plugin_info si =
	{
		.init = pinit,
		.get_last_error = pget_last_error,
		.destroy = pdestroy,
		.get_id = pget_id,
		.get_name = pget_name,
		.get_description = pget_description,
		.get_fields = pget_fields,
		.open = popen,
		.close = pclose,
		.next = pnext,
		.event_to_string = pevent_to_string,
		.extract_as_string = pextract_as_string
	};

	return si;
}
