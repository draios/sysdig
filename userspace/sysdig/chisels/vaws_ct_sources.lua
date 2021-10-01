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
	id = "ct_sources",
	name = "Sources",
	description = "Show the different CloudTrail event source types (eventSource in the json) and the number of events each source has generated.",
	tips = {"CloudTrail event sources include EC2, S3, ECS and the other many services AWS offers."},
	tags = {"csysdig-aws"},
	view_type = "table",
	applies_to = {"", "ct.name", "ct.user", "ct.useragent", "ct.region", "ct.srcip"},
	is_root = true,
	drilldown_target = "ct_events",
	use_defaults = false,
	columns = 
	{
		{
			name = "NA",
			field = "ct.shortsrc",
			is_key = true
		},
		{
			name = "SOURCE",
			description = "Name of the CloudTrail source service.",
			field = "ct.shortsrc",
			colsize = 32,
		},
		{
			name = "EVT COUNT",
			field = "evt.count",
			description = "The number of events the service has generated.",
			colsize = 12,
			aggregation = "SUM",
			is_sorting = true,
		},
	},
}
