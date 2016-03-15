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
	id = "spectro_tracers",
	name = "Tracers Spectrogram",
	description = "Application tracers latency spectrogram.",
	tips = {
		"This view offers a spectrogram-based representation of tracer return times.",
		"When appled to a selection in a view like 'Tracers' or 'Tracers List', this view will show only the latency of the selected tag, not the one of the childs. When applite to the whole machine, this view will show the latency of the 'root' tags, i.e. the tags with just one element.",
		"If you are in a tracer view like 'Tracers' or 'Tracers List', you can quickly show this spectrogram for a selection by clicking on F12.",
	},
	view_type = "spectrogram",
	applies_to = {"", "tracer.tag", "tracer.id", "container.id", "proc.pid", "thread.tid", "proc.name", "evt.res", "k8s.pod.id", "k8s.rc.id", "k8s.svc.id", "k8s.ns.id", "fd.name", "fd.containername", "fd.directory", "fd.containerdirectory"},
	filter = "tracer.ntags=%depth+1",
	use_defaults = false,
	drilldown_target = "tracer_ids",
	propagate_filter = false,
	columns = 
	{
		{
			name = "NA",
			field = "tracer.latency.quantized",
			is_key = true
		},
		{
			name = "LATENCY",
			description = "tracer latency. This determines the horizontal position of a dot in the chart.",
			field = "tracer.latency.quantized",
		},
		{
			name = "COUNT",
			description = "number of times a tracer falls in a certain latency bucket. This determines the color of a dot in the chart.",
			field = "evt.count",
			aggregation = "SUM",
		}
	}
}
