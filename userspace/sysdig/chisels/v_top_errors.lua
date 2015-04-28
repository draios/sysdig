--[[
Copyright (C) 2013-2015 Draios inc.
 
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
	id = "errors",
	name = "Errors",
	description = "This view shows the top system call errors, sorted by number of occurrences. Errors are shows as errno codes. Do a 'man errno' to find the meaning of the most important codes.",
	tips = {
		"This view can be applied not only to the whole machine, but also to single processes, containers, threads and so on. Use it after a drill down for more fine grained investigation.",
		"Drill down on an error by clicking enter to see which processes are generating it."
	},
	tags = {"Default"},
	view_type = "table",
	applies_to = {"all", "container.id", "proc.pid", "proc.name", "thread.tid", "fd.sport", "fd.directory"},
	filter = "evt.res != SUCCESS",
	use_defaults = true,
	drilldown_target = "procs",
	columns = 
	{
		{
			name = "NA",
			field = "evt.res",
			is_key = true
		},
		{
			name = "COUNT",
			field = "evt.count",
			description = "The number of times the error happened.",
			colsize = 12,
			aggregation = "SUM"
		},
		{
			name = "ERROR",
			description = "The error 'errno' code. Do a 'man errno' to find the meaning of the most important codes.",
			field = "evt.res",
			colsize = 200
		}
	}
}
