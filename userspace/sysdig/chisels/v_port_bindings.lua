--[[
Copyright (C) 2017 Draios inc.
 
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
	id = "port_bindings",
	name = "Port bindings",
	description = "Lists the creation (bind) and removal (close) of listening ports on the system.",
	tags = {"default", "wsysdig", "nocsysdig"},
	view_type = "list",
	applies_to = {""},
	filter = "(evt.type=bind and evt.dir=< and fd.type=ipv4) or (evt.type=close and evt.dir=> and fd.typechar=2 and fd.type=ipv4)",
	use_defaults = true,
	columns = 
	{
		{
			name = "TIME",
			field = "evt.time",
			description = "Time when the action happened.",
			colsize = 12,
		},
		{
			name = "OPERATION",
			field = "evt.type",
			description = "Action type. Can Be 'bind' (when a new listening port is added) or 'close' (when a listening port is removed).",
			colsize = 24,
		},
		{
			name = "PORT",
			field = "fd.sport",
			description = "The number of the created/removed port.",
			colsize = 24,
		},
		{
			name = "Command",
			description = "The full command line of the process adding/removing the port.",
			field = "proc.exeline",
			aggregation = "MAX",
			colsize = 0
		}
	}
}
