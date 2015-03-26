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
	name = "Top Connections",
	description = "Top Connections with conyainer context.",
	tags = {"Containers"},
	viewtype = "table",
	applies_to = "all,container.id,proc.pid,thread.tid,proc.name",
	filter = "fd.type=ipv4 and fd.name!=''",
	use_defaults = true,
	columns = 
	{
		{
			name = "NA",
			field = "fd.containername",
			is_key = true
		},
		{
			name = "IO CALLS",
			field = "evt.count",
			colsize = 12,
			aggregation = "SUM"
		},
		{
			is_sorting = true,
			name = "BYTES IN",
			field = "evt.buflen.net.in",
			colsize = 12,
			aggregation = "SUM"
		},
		{
			name = "BYTES OUT",
			field = "evt.buflen.net.out",
			colsize = 12,
			aggregation = "SUM"
		},
		{
			name = "Container",
			field = "container.name",
			colsize = 15
		},
		{
			name = "FILENAME",
			field = "fd.name",
			colsize = 200,
			aggregation = "SUM"
		}
	}
}
