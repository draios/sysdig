/*
Copyright (C) 2020 Sysdig Inc.

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

#include <vector>

class sinsp;
class chisel_desc;

//
// Printer functions
//
void list_fields(bool verbose, bool markdown, bool names_only=false);
void list_events(sinsp* inspector);

#ifdef HAS_CHISELS
void print_chisel_info(chisel_desc* cd);
void list_chisels(std::vector<chisel_desc>* chlist, bool verbose);
#endif
