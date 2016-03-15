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
	id = "tracer_ids",
	name = "Tracers List",
	description = "Show the list of application tracer requests. For each request, the view reports information like its arguments and how long it took to complete.",
	tips = {
		"Tracers are sysdig's super easy way to delimit portions of your code so that sysdig can measure how long they take and tell you what's happening in them. You can learn about tracers at XXX.",
		"For makers with hierarchical tags (e.g. 'api.loginrequest.processing'), only one level in the hierarch is shown (e.g. 'api'). Drilling down allows you to explore the next level.",
		"Since this view shows every single market call as a separate line, it can easily become crowded. The 'Tracers' view offer a more compact representation by collapsing requests with the same tag in a singlew line.",
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
