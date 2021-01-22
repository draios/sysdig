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
	id = "ct_logins",
	name = "Logins",
	description = "List all the AWS logins and the MFA authentications.",
	tips = {"A user can be an ineractive user or an API one. It can also be an AWS service or account. Drill down to see what type of events a user has generated."},
	tags = {"csysdig-aws"},
	view_type = "table",
	applies_to = {"", "ct.name", "ct.src", "ct.useragent", "ct.region", "ct.srcip"},
	is_root = false,
	filter = "ct.name = ConsoleLogin or ct.name = CheckMfa",
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
			description = ".",
			field = "ct.time",
			colsize = 22,
			is_sorting = true,
		},
		{
			name = "EVENT TYPE",
			description = ".",
			field = "ct.name",
			colsize = 16,
		},
		{
			name = "USER NAME",
			description = "Name of the user or service.",
			field = "ct.user",
			colsize = 35,
		},
		{
			name = "SRC IP",
			description = ".",
			field = "ct.srcip",
			colsize = 16,
		},
		{
			name = "MOBILE",
			description = ".",
			field = "jevt.value[/additionalEventData/MobileVersion]",
			colsize = 16,
		},
		{
			name = "LOGIN URL",
			description = ".",
			field = "jevt.value[/additionalEventData/LoginTo]",
			colsize = 350,
		},
	},
}
