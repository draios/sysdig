/*
Copyright (C) 2013-2018 Draios Inc dba Sysdig.

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

wh_t* scap_windows_hal_open(char* error);
void scap_windows_hal_close(wh_t* handle);
void scap_get_machine_info_windows(OUT uint32_t* num_cpus, OUT uint64_t* memory_size_bytes);
int32_t scap_create_userlist_windows(scap_t* handle);
int32_t scap_create_iflist_windows(scap_t* handle);
int32_t scap_get_procs_windows(scap_t* handle, char *error);
