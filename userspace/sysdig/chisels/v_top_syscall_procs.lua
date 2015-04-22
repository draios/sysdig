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
	id = "top_syscall_procs",
	name = "Top Syscall Callers",
	description = "Show the top processes based on number of system call invocations and time spent calling them.",
	tags = {"Default"},
	view_type = "table",
	applies_to = "evt.type",
	use_defaults = true,
	filter = "syscall.type exists",
	columns = 
	{
		{
			name = "NA",
			field = "proc.pid",
			is_key = true
		},
		{
			is_sorting = true,
			name = "COUNT",
			field = "evt.count",
			description = "Number of system calls this process has invoked.",
			colsize = 10,
			aggregation = "SUM"
		},
		{
			name = "TIME",
			field = "evt.latency",
			description = "Total time spent on system calls by the process.",
			colsize = 10,
			aggregation = "SUM"
		},
		{
			tags = {"containers"},
			name = "Container",
			field = "container.name",
			description = "Name of the container. What this field contains depends on the containerization technology. For example, for docker this is the content of the 'NAMES' column in 'docker ps'",
			colsize = 15
		},
		{
			name = "Command",
			description = "The full command line of the process.",
			field = "proc.exeline",
			colsize = 200
		}
	}
}
