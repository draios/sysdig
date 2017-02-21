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

view_infoz = 
{
	id = "cores",
	name = "CPUs",
	description = "This is the typical top/htop process list, showing usage of resources like CPU, memory, disk and network on a by process basis.",
	tags = {"Default"},
	view_type = "table",
	applies_to = {"", "container.id", "proc.pid", "k8s.pod.id", "k8s.rc.id", "k8s.rs.id", "k8s.svc.id", "k8s.ns.id", "marathon.app.id", "marathon.group.name", "mesos.task.id", "mesos.framework.name"},
	is_root = true,
	use_defaults = true,
	drilldown_target = "procs",
	columns = 
	{
		{
			name = "NA",
			field = "proc.pid",
			is_key = true
		},
		{
			name = "NA",
			field = "evt.cpu",
			is_groupby_key = true
		},
		{
			name = "CORE",
			description = "CPU or Core ID.",
			field = "evt.cpu",
			colsize = 8,
		},
		{
			name = "CPU",
			field = "proc.cpu",
			description = "CPU usage.",
			colsize = 8,
			aggregation = "AVG",
			groupby_aggregation = "SUM",
			is_sorting = true
		},
		{
			name = "TH",
			field = "proc.nthreads",
			description = "Number of threads that the process contains.",
			aggregation = "MAX",
			groupby_aggregation = "SUM",
			colsize = 5
		}
	}
}
