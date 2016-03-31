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
	id = "trace_list",
	name = "Trace List",
	description = "Show the detailed list of traces. For each trace, the view reports information like its arguments and how long it took to complete.",
	tips = {
		"Traces are sysdig's super easy way to delimit portions of your code so that sysdig can measure how long they take and tell you what's happening inside them. You can learn about tracers at XXX.",
		"Only the root trace spans (i.e. the spans with only one tag) are shown when this view is applied to the whole machine. Drilling down allows you to explore the child spans.",
	},
	tags = {"Default"},
	view_type = "table",
	applies_to = {"", "tracer.tag", "tracer.id", "container.id", "proc.pid", "proc.name", "thread.tid", "fd.directory", "evt.res", "k8s.pod.id", "k8s.rc.id", "k8s.svc.id", "k8s.ns.id"},
	use_defaults = true,
	filter = "tracer.ntags>=%depth+1",
	drilldown_target = "tracer_ids",
	drilldown_increase_depth = true,
	columns = 
	{
		{
			name = "NA",
			field = "tracer.idtag[%depth]",
			is_key = true
		},
		{
			name = "ID",
			field = "tracer.id",
			description = "the unique numeric ID of the tracer.",
			colsize = 10,
		},
		{
			name = "TIME",
			field = "tracer.latency.fortag[%depth]",
			description = "the time this tracer call took to complete",
			colsize = 10,
			aggregation = "AVG",
			is_sorting = true,
		},
		{
			name = "TAG",
			field = "tracer.tag[%depth]",
			description = "tracer tag.",
			colsize = 32,
			aggregation = "SUM"
		},
		{
			name = "ARGS",
			field = "tracer.enterargs",
			description = "tracer enter arguments.",
			colsize = 256,
			aggregation = "SUM"
		},
	}
}
