/*
Copyright (C) 2013-2020 Draios Inc dba Sysdig.

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

//
// This is the opaque pointer to the state of a source plugin.
// It points to any data that the pluging might need to operate. It is 
// allocated by init() and must be destroyed by destroy().
//
typedef void src_plugin_t;
typedef void src_instance_t;

typedef struct
{
	//
	// Initialize the plugin and, if needed, allocate its state.
	// This method is optional.
	//
	src_plugin_t* (*init)(char* config, char *error, int32_t* rc);
	//
	// Destroy the plugin and, if plugin state was allocated, free it.
	// This method is optional.
	//
	void (*destroy)(src_plugin_t* s);
	//
	// Return the unique ID of the plugin. 
	// EVERY PLUGIN MUST OBTAIN AN OFFICIAL ID FROM THE FALCO ORGANIZATION,
	// OTHERWISE IT WON'T PROPERLY WITH OTHER PLUGINS.
	// This method is required.
	//
	uint32_t (*get_id)();
	//
	// Open the source and start a capture.
	// This method is required.
	//
	src_instance_t* (*open)(src_plugin_t* s, char *error, int32_t* rc);
	//
	// Open the source and start a capture.
	// This method is required.
	//
	void (*close)(src_plugin_t* s, src_instance_t* h);
	//
	// Return the next event.
	// This method is required.
	//
	int32_t (*next)(src_plugin_t* s, src_instance_t* h, uint8_t** data, uint32_t* datalen);

	src_plugin_t* state;
	src_instance_t* handle;
	uint32_t id;
} scap_src_info;


int32_t scap_source_register(scap_src_info* src_info, char* config, char *error, int32_t* rc);
