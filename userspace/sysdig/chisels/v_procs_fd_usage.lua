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
	id = "procs_fd_usage",
	name = "Processes FD Usage",
	description = "This view summarizes file descriptor usage for the processes in the system.",
	tips = {
	"A process that reaches its FD limit will very likely be killed by the OS. As a consequence, processes for which the OPEN column value is close to the MAX column value (or which, alternatively, have a PCT value close to 100) deserve particular attention.",
	"Clicking enter on a selection will show the activity I/O activity done by the process on different families of FDs."},
	tags = {"Default"},
	view_type = "table",
	applies_to = {"", "container.id", "fd.name", "fd.sport", "evt.type", "fd.directory", "fd.type"},
	is_root = true,
	drilldown_target = "io_by_type",
	use_defaults = true,
	columns = 
	{
		{
			name = "NA",
			field = "proc.pid",
			is_key = true
		},
		{
			name = "PID",
			description = "Process PID.",
			field = "proc.pid",
			colsize = 8,
		},
		{
			tags = {"containers"},
			name = "VPID",
			field = "proc.vpid",
			description = "PID that the process has inside the container.",
			colsize = 8,
		},
		{
			name = "OPEN",
			field = "proc.fdopencount",
			description = "Number of open FDs that the process currently has. On a trace file, this is the maximum value reached by the process over the whole file.",
			aggregation = "MAX",
			colsize = 8,
			is_sorting = true,
		},
		{
			name = "MAX",
			field = "proc.fdlimit",
			description = "Maximum number of FDs that this process can open.",
			aggregation = "MAX",
			colsize = 8,
		},
		{
			name = "PCT",
			field = "proc.fdusage",
			description = "Percentage of currently open FDs versus the maximum allows for this process. In other words, this euquals to OPEN * 100 / MAX, and can be used to quickly identify processes that are getting close to their limit.",
			aggregation = "MAX",
			colsize = 8,
		},
		{
			tags = {"containers"},
			name = "The container this process belongs to.",
			field = "container.name",
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
