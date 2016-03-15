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
	id = "tracers",
	name = "Tracers",
	description = "Show a summary of the application tracers executing on the system. For each tracer tag, the view reports information like how many times it's been called and how long it took to complete.",
	tips = {
		"Tracers are sysdig's super easy way to delimit portions of your code so that sysdig can measure how long they take and tell you what's happening in them. You can learn about tracers at XXX.",
		"For makers with hierarchical tags (e.g. 'api.loginrequest.processing'), only one level in the hierarch is shown (e.g. 'api'). Drilling down allows you to explore the next level.",
		"This view collapses multiple calls to a tag into a single line. If you instead want to see each single call, use the 'Tracers List' view.",
	},
	tags = {"Default"},
	view_type = "table",
	applies_to = {"", "tracer.tag", "tracer.id", "container.id", "proc.pid", "proc.name", "thread.tid", "fd.directory", "evt.res", "k8s.pod.id", "k8s.rc.id", "k8s.svc.id", "k8s.ns.id"},
	use_defaults = true,
	filter = "tracer.ntags>=%depth+1",
	drilldown_target = "tracers",
	spectro_type = "tracers",
	drilldown_increase_depth = true,
	columns = 
	{
		{
			name = "NA",
			field = "tracer.tag[%depth]",
			is_key = true
		},
		{
			is_sorting = true,
			name = "HITS",
			field = "tracer.count.fortag[%depth]",
			description = "number of times the tracer with the given tag has been hit.",
			colsize = 10,
			aggregation = "SUM"
		},
		{
			name = "AVG TIME",
			field = "tracer.latency.fortag[%depth]",
			description = "the average time this tracer took to complete.",
			colsize = 10,
			aggregation = "AVG"
		},
		{
			name = "MIN TIME",
			field = "tracer.latency.fortag[%depth]",
			description = "the minimum time this tracer took to complete.",
			colsize = 10,
			aggregation = "MIN"
		},
		{
			name = "MAX TIME",
			field = "tracer.latency.fortag[%depth]",
			description = "the maximum time this tracer took to complete.",
			colsize = 10,
			aggregation = "MAX"
		},
		{
			name = "CHD HITS",
			field = "tracer.childcount.fortag[%depth]",
			description = "number of times any child of the tracer with the given tag has been hit. This is useful to determine if the tracer is a leaf or if it has childs nested in it.",
			colsize = 10,
			aggregation = "SUM"
		},
		{
			name = "TAG",
			field = "tracer.tag[%depth]",
			description = "tracer tag.",
			colsize = 256,
			aggregation = "SUM"
		},
	}
}
