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
	id = "ct_events_key",
	name = "Event Types - Key",
	description = "Show the 'key' CloudTrail event types and the number of times each of them occurs.\nA key event is an event that changes the state of the infrastructure. Examples of 'key' actions: starting or stopping instances, creating resources, modifying configurations, etc.",
	tips = {"Each AWS source has a unique set of events it can produce. You can learn more about what an event means in the CloudTrail User Guide (https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)"},
	tags = {"csysdig-aws"},
	view_type = "table",
	applies_to = {"", "ct.user", "ct.shortsrc", "ct.useragent", "ct.region", "ct.srcip", "s3.uri", "s3.bucket"},
	is_root = false,
	filter = "ct.is_key=true",
	drilldown_target = "ct_events_list",
	use_defaults = false,
	columns = 
	{
		{
			name = "NA",
			field = "ct.name",
			is_key = true
		},
		{
			name = "EVT NAME",
			description = "Name of the CloudTrail event.",
			field = "ct.name",
			colsize = 32,
		},
		{
			name = "SERVICE",
			description = "Service generating the event.",
			field = "ct.shortsrc",
			colsize = 24,
		},
		{
			name = "COUNT",
			field = "evt.count",
			description = "The number of times the event has been generated.",
			colsize = 12,
			aggregation = "SUM",
			is_sorting = true,
		},
	},
}
