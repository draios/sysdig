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
	id = "ct_new_instances",
	name = "EC2 Instance Starts",
	description = "List all of EC2 instances that have been started.",
	tips = {"Each line in this view includes useful fields like the instance name (when present), its type, the start time, etc. For the full details, select an item and echo its JSON ('e' keyboard shortcut)."},
	tags = {"csysdig-aws"},
	view_type = "table",
	applies_to = {"", "ct.name", "ct.shortsrc", "ct.useragent", "ct.region", "ct.srcip"},
	is_root = false,
	filter = "ct.name = RunInstances",
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
			name = "START TIME",
			description = "Instance start time.",
			field = "evt.datetime.s",
			colsize = 22,
			is_sorting = true,
		},
		{
			name = "INSTANCE TYPE",
			description = "Instance type.",
			field = "jevt.value[/requestParameters/instanceType]",
			colsize = 16,
		},
		{
			name = "USER NAME",
			description = "Name of the user that who started the instance.",
			field = "ct.user",
			colsize = 35,
		},
		{
			name = "USER IP",
			description = "IP address the of the user who started the instance.",
			field = "ct.srcip",
			colsize = 16,
		},
		{
			name = "INSTANCE NAME",
			description = "Name of the instance, i.e. the value of the 'Name' tag when present.",
			field = "ec2.name",
			colsize = 360,
		},
	},
}
