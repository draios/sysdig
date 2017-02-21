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
	id = "io_by_type",
	name = "I/O by Type",
	description = "Show an overview of the I/O volume based on I/O type. Possible I/O types are: file, directory, ipv4 or ipv6 network traffic, pipe, unix socket, signal fd, event fd, inotify fd.",
	tips = {"This view is a good starting point to understand what a machine is doing besides CPU computation. Remeber that you can apply it to a process or to a container as well, to get an overview of what they are doing."},
	tags = {"Default"},
	view_type = "table",
	applies_to = {"", "container.id", "proc.pid", "proc.name", "thread.tid", "fd.sport", "fd.sproto", "evt.res", "k8s.pod.id", "k8s.rc.id", "k8s.rs.id", "k8s.svc.id", "k8s.ns.id", "marathon.app.id", "marathon.group.name", "mesos.task.id", "mesos.framework.name"},
	use_defaults = true,
	drilldown_target = "procs",
	columns = 
	{
		{
			name = "NA",
			field = "fd.type",
			is_key = true
		},
		{
			name = "BPS IN",
			field = "evt.buflen.in",
			description = "Bytes per second read from the FDs of the specific type.",
			colsize = 12,
			aggregation = "TIME_AVG"
		},
		{
			name = "BPS OUT",
			field = "evt.buflen.out",
			description = "Bytes per second written to the FDs of the specific type.",
			colsize = 12,
			aggregation = "TIME_AVG"
		},
		{
			is_sorting = true,
			name = "IOPS",
			field = "evt.count",
			description = "Number of I/O operations for the specified I/O category. This counts all the operations on the file, including, open, close, read, write, stat, and so on. As a consequence, this value can be nonzero even if I/O bytes for the file are zero.",
			colsize = 9,
			aggregation = "TIME_AVG"
		},
		{
			name = "TIME",
			field = "evt.latency",
			description = "Time spent by processes doing any I/O operation (including wait) of this type.",
			colsize = 9,
			aggregation = "SUM"
		},
		{
			name = "I/O Type",
			field = "fd.type",
			description = "Type of I/O. Can be one of: file, directory, ipv4, ipv6, pipe, unix, signal, event, inotify",
			aggregation = "SUM",
			colsize = 0
		},
	}
}
