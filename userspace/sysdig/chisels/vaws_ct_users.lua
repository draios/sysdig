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
	id = "ct_users",
	name = "Users",
	description = "Show the different AWS users and the number of events each user has generated.",
	tips = {"A user can be an ineractive user or an API one. It can also be an AWS service or account. Drill down to see what type of events a user has generated."},
	tags = {"csysdig-aws"},
	view_type = "table",
	applies_to = {"", "ct.name", "ct.shortsrc", "ct.useragent", "ct.region", "ct.srcip", "s3.uri", "s3.bucket"},
	is_root = false,
	drilldown_target = "ct_sources",
	use_defaults = false,
	columns = 
	{
		{
			name = "NA",
			field = "ct.user",
			is_key = true
		},
		{
			name = "USER NAME",
			description = "Name of the user or service.",
			field = "ct.user",
			colsize = 48,
		},
		{
			name = "EVT COUNT",
			field = "evt.count",
			description = "The number of events the user has generated.",
			colsize = 12,
			aggregation = "SUM",
			is_sorting = true,
		},
	},
}
