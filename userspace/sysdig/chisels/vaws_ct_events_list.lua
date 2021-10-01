--[[
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

--]]

view_info = 
{
	id = "ct_events_list",
	name = "Events List",
	description = "List all the cloudtrail events.",
	tips = {"This view prints one event per line, including details like time, user and source IP. It's a good view to drill down into a selection and see the detailed activity."},
	tags = {"csysdig-aws"},
	view_type = "table",
	applies_to = {"", "ct.name", "ct.shortsrc", "ct.useragent", "ct.region", "ct.srcip", "s3.uri", "s3.bucket"},
	is_root = false,
	drilldown_target = "echo",
	use_defaults = true,
	columns = 
	{
		{
			name = "NA",
			field = "ct.id",
			is_key = true
		},
		{
			name = "TIME",
			description = "The login time.",
			field = "evt.datetime.s",
			colsize = 22,
			is_sorting = true,
		},
		{
			name = "EVENT NAME",
			description = "The type of event.",
			field = "ct.name",
			colsize = 30,
		},
		{
			name = "SERVICE",
			description = "Service generating the event.",
			field = "ct.shortsrc",
			colsize = 24,
		},
		{
			name = "USER NAME",
			description = "Name of the user that generated the event.",
			field = "ct.user",
			colsize = 35,
		},
		{
			name = "SRC IP",
			description = "IP address that generated the event.",
			field = "ct.srcip",
			colsize = 20,
		},
		{
			name = "INFO",
			description = "Event details, if available for the event in the line.",
			field = "ct.info",
			colsize = 350,
		},
	},
}
