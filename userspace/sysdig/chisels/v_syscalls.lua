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
	id = "syscalls",
	name = "System Calls",
	description = "Show the top system calls in the system based on number of invocations and time spent calling them.",
	tips = {
		"This view is useful to spot not only system activity saturation, but also things like high wait time.", 
		"Drill down by clicking enter on a system call to see which processes are using it.",
		"The AVG TIME column is useful to identify system operations that tend to be consistently slow and can be the cause of bottlenecks."},
	tags = {"Default"},
	view_type = "table",
	applies_to = {"", "container.id", "proc.pid", "proc.name", "thread.tid", "fd.sport", "fd.sproto", "fd.name", "fd.directory", "evt.res", "k8s.pod.id", "k8s.rc.id", "k8s.rs.id", "k8s.svc.id", "k8s.ns.id", "marathon.app.id", "marathon.group.name", "mesos.task.id", "mesos.framework.name"},
	use_defaults = true,
	filter = "syscall.type exists",
	drilldown_target = "syscall_procs",
	columns = 
	{
		{
			name = "NA",
			field = "evt.type",
			is_key = true
		},
		{
			is_sorting = true,
			name = "CALLS/S",
			field = "evt.count",
			description = "Number of calls per second for this system call.",
			colsize = 10,
			aggregation = "TIME_AVG"
		},
		{
			name = "TOT TIME",
			field = "evt.latency",
			description = "Total time spent waiting for the given system call to return.",
			colsize = 10,
			aggregation = "SUM"
		},
		{
			name = "AVG TIME",
			field = "evt.latency",
			description = "Average time spent in the given system call. This is calculated dividing the value under TOT TIME by the value under COUNT.",
			colsize = 10,
			aggregation = "AVG"
		},
		{
			name = "SYSCALL",
			field = "evt.type",
			description = "System call name.",
			colsize = 32,
			aggregation = "SUM"
		},
	}
}
