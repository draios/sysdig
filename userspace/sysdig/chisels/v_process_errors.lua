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
	id = "process_errors",
	name = "Process Errors",
	description = "This view shows system error information counters for processes. Errors are reported according to 4 categories: file I/O, network I/O, memory allocation and 'other'.",
	tips = {
		"If you click enter on a selection in this chart, you will be able to see the specific errors that the process is generating.",
		"Diggin into a process by clicking on F6 will let you explore the system calls for that specific process and see the full details about each error."
	},
	tags = {"Default"},
	view_type = "table",
	applies_to = "all,container.id,fd.name,fd.sport,evt.type,fd.directory",
	drilldown_target = "top_errors",
	use_defaults = true,
	columns = 
	{
		{
			name = "NA",
			field = "proc.pid",
			is_key = true
		},
		{
			name = "FILE",
			field = "evt.count.error.file",
			description = "Number of file I/O errors.",
			colsize = 8,
			aggregation = "SUM"
		},
		{
			name = "NET",
			field = "evt.count.error.net",
			description = "Number of network I/O errors.",
			colsize = 8,
			aggregation = "SUM"
		},
		{
			name = "MEMORY",
			field = "evt.count.error.memory",
			description = "Number of memory allocation/release related errors.",
			colsize = 8,
			aggregation = "SUM"
		},
		{
			name = "OTHER",
			field = "evt.count.error.other",
			description = "Number of errors that don't fall in any of the previous categories. E.g. signal or event related errors.",
			colsize = 8,
			aggregation = "SUM"
		},
		{
			name = "PID",
			description = "Process PID.",
			field = "proc.pid",
			colsize = 8,
		},
		{
			name = "Command",
			description = "Full command line of the process.",
			field = "proc.exeline",
			colsize = 200
		}
	}
}
