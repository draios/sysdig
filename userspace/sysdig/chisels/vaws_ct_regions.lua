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
	id = "ct_regions",
	name = "Regions",
	description = "Show the different AWS regions and the number of events each one has generated.",
	tips = {"Drill down into one of the regions to see what type of events were generated in it."},
	tags = {"csysdig-aws"},
	view_type = "table",
	applies_to = {"", "ct.name", "ct.user", "ct.shortsrc", "ct.useragent", "ct.srcip"},
	is_root = false,
	drilldown_target = "ct_sources",
	use_defaults = false,
	columns = 
	{
		{
			name = "NA",
			field = "ct.region",
			is_key = true
		},
		{
			name = "REGION",
			description = "The AWS region generating the events.",
			field = "ct.region",
			colsize = 32,
		},
		{
			name = "EVT COUNT",
			field = "evt.count",
			description = "The number of events the region has generated.",
			colsize = 12,
			aggregation = "SUM",
			is_sorting = true,
		},
	},
}
