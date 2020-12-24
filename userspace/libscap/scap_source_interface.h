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

#pragma once

//
// This is the opaque pointer to the state of a source plugin.
// It points to any data that might be needed plugin-wise. It is 
// allocated by init() and must be destroyed by destroy().
//
typedef void src_plugin_t;

//
// This is the opaque pointer to the state of an open instance of the source 
// plugin.
// It points to any data that is needed while a capture is running. It is 
// allocated by open() and must be destroyed by close().
//
typedef void src_instance_t;

//
// This is the interface of a scap source plugin
//
typedef struct
{
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

	//
	// The following members are PRIVATE for the engine and should not be touched.
	//
	src_plugin_t* state;
	src_instance_t* handle;
	uint32_t id;
} scap_src_interface;
