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
	id = "procs",
	name = "Processes",
	description = "This is the typical top/htop process list, showing usage of resources like CPU, memory, disk and network on a by process basis.",
	tips = {"This is a perfect view to start a drill down session. Click enter or double click on a process to dive into it and explore its behavior."},
	tags = {"Default", "wsysdig"},
	view_type = "table",
	filter = "evt.type!=switch",
	applies_to = {"", "container.id", "fd.name", "fd.containername", "fd.sport", "fd.sproto", "evt.type", "fd.directory", "fd.containerdirectory", "fd.type", "k8s.pod.id", "k8s.rc.id", "k8s.rs.id", "k8s.svc.id", "k8s.ns.id", "marathon.app.id", "marathon.group.name", "mesos.task.id", "mesos.framework.name"},
	is_root = true,
	drilldown_target = "threads",
	use_defaults = true,
	columns = 
	{
		{
			name = "NA",
			field = "thread.tid",
			is_key = true
		},
		{
			name = "NA",
			field = "proc.pid",
			is_groupby_key = true
		},
		{
			name = "PID",
			description = "Process PID.",
			field = "proc.pid",
			colsize = 7,
		},
		{
			tags = {"containers"},
			name = "VPID",
			field = "proc.vpid",
			description = "PID that the process has inside the container.",
			colsize = 8,
		},
		{
			name = "CPU",
			field = "thread.cpu",
			description = "Amount of CPU used by the proccess.",
			aggregation = "AVG",
			groupby_aggregation = "SUM",
			colsize = 8,
			is_sorting = true
		},
		{
			name = "USER",
			field = "user.name",
			colsize = 12
		},
		{
			name = "TH",
			field = "proc.nthreads",
			description = "Number of threads that the process contains.",
			aggregation = "MAX",
			groupby_aggregation = "MAX",
			colsize = 5
		},
		{
			name = "VIRT",
			field = "thread.vmsize.b",
			description = "Total virtual memory for the process.",
			aggregation = "MAX",
			groupby_aggregation = "MAX",
			colsize = 9
		},
		{
			name = "RES",
			field = "thread.vmrss.b",
			description = "Resident non-swapped memory for the process.",
			aggregation = "MAX",
			groupby_aggregation = "MAX",
			colsize = 9
		},
		{
			name = "FILE",
			field = "evt.buflen.file",
			description = "Total (input+output) file I/O bandwidth generated by the process, in bytes per second.",
			aggregation = "TIME_AVG",
			groupby_aggregation = "SUM",
			colsize = 8
		},
		{
			name = "NET",
			field = "evt.buflen.net",
			description = "Total (input+output) network I/O bandwidth generated by the process, in bytes per second.",
			aggregation = "TIME_AVG",
			groupby_aggregation = "SUM",
			colsize = 8
		},
		{
			tags = {"containers"},
			name = "CONTAINER",
			field = "container.name",
			colsize = 20
		},
		{
			name = "Command",
			description = "The full command line of the process.",
			field = "proc.exeline",
			aggregation = "MAX",
			colsize = 0
		}
	},
	actions = 
	{
		{
			hotkey = "9",
			command = "kill -9 %proc.pid",
			description = "kill -9",
			ask_confirmation = true,
			wait_finish = false
		},
		{
			hotkey = "c",
			command = "gcore %proc.pid",
			description = "generate core",
		},
		{
			hotkey = "g",
			command = "gdb -p %proc.pid",
			description = "gdb attach",
			wait_finish = false
		},
		{
			hotkey = "k",
			command = "kill %proc.pid",
			description = "kill",
			ask_confirmation = true,
			wait_finish = false
		},
		{
			hotkey = "l",
			command = "ltrace -p %proc.pid",
			description = "ltrace",
		},
		{
			hotkey = "s",
			command = "gdb -p %proc.pid --batch --quiet -ex \"thread apply all bt full\" -ex \"quit\"",
			description = "print stack",
		},
		{
			hotkey = "f",
			command = "lsof -p %proc.pid",
			description = "one-time lsof",
		},
		{
			hotkey = "[",
			command = "renice $(expr $(ps -h -p %proc.pid -o nice) + 1) -p %proc.pid",
			description = "increment nice by 1",
			wait_finish = false,
		},
		{
			hotkey = "]",
			command = "renice $(expr $(ps -h -p %proc.pid -o nice) - 1) -p %proc.pid",
			description = "decrement nice by 1",
			wait_finish = false,
		},
	},
}
