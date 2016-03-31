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
	id = "spans_list",
	name = "spans List",
	description = "Show the detailed list of a tracer selection's child spans. For each span type, the view reports information like its arguments and how long it took to complete.",
	tips = {
		"Only the spans spans that are direct childs of the selection (i.e. the spans with one more tag than the selection) are shown. Drilling down allows you to explore the further levels.",
	},
	tags = {"Default"},
	view_type = "table",
	applies_to = {"", "span.tag", "span.id", "container.id", "proc.pid", "proc.name", "thread.tid", "fd.directory", "evt.res", "k8s.pod.id", "k8s.rc.id", "k8s.svc.id", "k8s.ns.id"},
	use_defaults = true,
	filter = "span.ntags>=%depth+1",
	drilldown_target = "spans_list",
	drilldown_increase_depth = true,
	columns = 
	{
		{
			name = "NA",
			field = "span.idtag[%depth]",
			is_key = true
		},
		{
			name = "ID",
			field = "span.id",
			description = "the unique numeric ID of the span.",
			colsize = 10,
		},
		{
			name = "TIME",
			field = "span.duration.fortag[%depth]",
			description = "the time this span call took to complete",
			colsize = 10,
			aggregation = "AVG",
			is_sorting = true,
		},
		{
			name = "TAG",
			field = "span.tag[%depth]",
			description = "span tag.",
			colsize = 32,
			aggregation = "SUM"
		},
		{
			name = "ARGS",
			field = "span.enterargs",
			description = "span enter arguments.",
			colsize = 256,
			aggregation = "SUM"
		},
	}
}
