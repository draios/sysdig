/*
Copyright (C) 2013-2019 Draios Inc dba Sysdig.

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

#include "runc.h"

#include <cstring>

#include "sinsp.h"
#include "sinsp_int.h"

namespace {

const size_t CONTAINER_ID_LENGTH = 64;
const size_t REPORTED_CONTAINER_ID_LENGTH = 12;
const char* CONTAINER_ID_VALID_CHARACTERS = "0123456789abcdefABCDEF";

static_assert(REPORTED_CONTAINER_ID_LENGTH <= CONTAINER_ID_LENGTH, "Reported container ID length cannot be longer than actual length");

// check if cgroup ends with <prefix><container_id><suffix>
// If true, set <container_id> to a truncated version of the id and return true.
// Otherwise return false and leave container_id unchanged
bool match_one_container_id(const std::string &cgroup, const std::string &prefix, const std::string &suffix, std::string &container_id)
{
	// Short and return early for trivial candidates
	if(cgroup.length() < (CONTAINER_ID_LENGTH + prefix.length() + suffix.length())) {
		return false;
	}
	
	// We search the cgroup string from backwards to front; splitting
	// it using the '/' char delimiter. We use this as the basis for
	// analysing cgroups. Once we have a string of desired length , we then
	// analyze it to make sure it matches a container id pattern
	size_t start_pos = cgroup.size()-1, end_pos = cgroup.size()-1; // These keep track of individual substring postions between '/'
	size_t start_c_id; // This keeps track of the individual container id start postion

	while((start_pos = cgroup.rfind("/",start_pos)) != std::string::npos) {

		std::string sub_string = cgroup.substr(start_pos, end_pos - start_pos + 1);

		// Only proceed for those substrings that are of required length
		if(sub_string.length() >= ( CONTAINER_ID_LENGTH + prefix.length() + suffix.length())) {
			// prefix and suffix matching
			start_c_id = sub_string.find(prefix);
			size_t end_c_id = sub_string.rfind(suffix);

			// Proceed only if both prefix and suffix are matched
			if(start_c_id != std::string::npos && end_c_id != std::string::npos) {
				// both prefix and suffix match
				start_c_id = start_pos + prefix.size();

				// Now final container id match
				size_t invalid_ch_pos = cgroup.find_first_not_of(CONTAINER_ID_VALID_CHARACTERS, start_c_id);
				if ((invalid_ch_pos == std::string::npos) || (invalid_ch_pos - start_c_id == CONTAINER_ID_LENGTH)) {
					// A container id is likely found because
					// a.) We went to end of string without finding an invalid char
					// b.) we found a container id of length CONTAINER_ID_LENGTH
					break;
				}
			}
		}

		// if the program reaches here; the current
		// sub_string that we processed does not match
		// a container id. Reset limits for next iteration
		// and continue

		if(start_pos == 0) {
			// Already at the start ; no use continuing
			return false;
		}

		// Reset limits for next iteration
		end_pos = start_pos - 1;
		start_pos--;
		if(end_pos < (CONTAINER_ID_LENGTH + prefix.length() + suffix.length())) {
			// Remaining string is too short to find container id
			// No use continuing.
			return false;
		}
	}

	// return final container id
	container_id = cgroup.substr(start_c_id, REPORTED_CONTAINER_ID_LENGTH);
	return true;
}

bool match_container_id(const std::string &cgroup, const libsinsp::runc::cgroup_layout *layout,
			std::string &container_id)
{
	for(size_t i = 0; layout[i].prefix && layout[i].suffix; ++i)
	{
		if(match_one_container_id(cgroup, layout[i].prefix, layout[i].suffix, container_id))
		{
			return true;
		}
	}

	return false;
}
}

namespace libsinsp {
namespace runc {

bool matches_runc_cgroups(const sinsp_threadinfo *tinfo, const cgroup_layout *layout, std::string &container_id)
{
	for(const auto &it : tinfo->m_cgroups)
	{
		if(match_container_id(it.second, layout, container_id))
		{
			return true;
		}
	}

	return false;
}
}
}
