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
	id = "page_faults",
	name = "Page Faults",
	description = "This view shows page fault counters for processes. Both minor and major page faults are reported for each process. The counters report the number of page faults since process start.",
	tips = {
		"Major page faults are typically the ones you really want to keep an eye on. They are the ones causing pages swapping to disk, thus dramatically slowing down process execution.",
		"When applying this view on a live system, if the system is well tuned for performance you should see no changes in the first column."
	},
	tags = {"Default"},
	view_type = "table",
	filter = "evt.type!=switch",
	applies_to = {"", "container.id", "fd.name", "fd.sport", "fd.sproto", "evt.type", "fd.directory", "k8s.pod.id", "k8s.rc.id", "k8s.rs.id", "k8s.svc.id", "k8s.ns.id", "marathon.app.id", "marathon.group.name", "mesos.task.id", "mesos.framework.name"},
	drilldown_target = "errors",
	use_defaults = true,
	columns = 
	{
		{
			name = "NA",
			field = "proc.pid",
			is_key = true
		},
		{
			name = "MAJOR",
			field = "thread.pfmajor",
			description = "Number of major page faults that the process generated since its start.",
			colsize = 9,
			aggregation = "MAX",
			is_sorting = true
		},
		{
			name = "MINOR",
			field = "thread.pfminor",
			description = "Number of minor page faults that the process generated since its start.",
			colsize = 9,
			aggregation = "MAX"
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
			tags = {"containers"},
			name = "Container",
			field = "container.name",
			description = "Name of the container. What this field contains depends on the containerization technology. For example, for docker this is the content of the 'NAMES' column in 'docker ps'",
			colsize = 20
		},
		{
			name = "Command",
			description = "Full command line of the process.",
			field = "proc.exeline",
			aggregation = "MAX",
			colsize = 0
		}
	}
}
