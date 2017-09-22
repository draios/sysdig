--[[
Copyright (C) 2013-2014 Draios inc.
 
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.


This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
--]]

view_info = 
{
	id = "notifications",
	name = "Notifications",
	description = "Lists the notification events that indicate the specific point in time when sysdig secure policies have been violated.",
	tags = {"nocsysdig"},
	view_type = "list",
	applies_to = {""},
	filter = "evt.type=notification",
	use_defaults = true,
	columns = 
	{
		{
			name = "TIME",
			field = "evt.time",
			description = "Time when the command was executed.",
			colsize = 12,
		},
		{
			name = "ID",
			field = "evt.arg.id",
			description = "Notification ID. This can be used to locate the notification in the sysdig secure user interface.",
			colsize = 24,
		},
		{
			tags = {"containers"},
			name = "Container",
			field = "container.name",
			colsize = 20
		},
		{
			name = "DESCRIPTION",
			field = "evt.arg.desc",
			description = "The description of the policy that generated this notification.",
			colsize = 0,
		}
	}
}
