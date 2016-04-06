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
	id = "spectro_traces",
	name = "Traces Spectrogram",
	description = "Traces duration spectrogram.",
	tips = {
		"This view offers a spectrogram-based representation of root trace spans durations.",
		"When appled to a selection in a view like 'Trace Summary' or 'Trace List', this view will only show the latency of the selected spans, while their parent and child spans won't be shown. When applied to the whole machine, this view will show the latency of the traces, i.e. the root spans that have just one tag.",
		"If you are in a trace view like 'Traces Summary' or 'Traces List', you can quickly show this spectrogram for a selection by clicking on F12.",
	},
	view_type = "spectrogram",
	applies_to = {"", "span.tag", "span.id", "container.id", "proc.pid", "thread.tid", "proc.name", "evt.res", "k8s.pod.id", "k8s.rc.id", "k8s.svc.id", "k8s.ns.id", "fd.name", "fd.containername", "fd.directory", "fd.containerdirectory"},
	filter = "span.ntags=%depth+1",
	use_defaults = false,
	drilldown_target = "traces_list",
	propagate_filter = false,
	columns = 
	{
		{
			name = "NA",
			field = "span.duration.quantized",
			is_key = true
		},
		{
			name = "LATENCY",
			description = "span latency. This determines the horizontal position of a dot in the chart.",
			field = "span.duration.quantized",
		},
		{
			name = "COUNT",
			description = "number of times a span falls in a certain latency bucket. This determines the color of a dot in the chart.",
			field = "evt.count",
			aggregation = "SUM",
		}
	}
}
