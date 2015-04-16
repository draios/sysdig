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

view_info = 
{
	id = "LD_top_sports",
	name = "Top Server Ports",
	description = "This view lists all of the server ports in terms of network bandwidth usage.",
	tips = {"Want to restrict this visualization to a single process or container? Just drill down into them before applying it.", 
		"Select a port and drill down with the 'Top Processes' view to see which processes are generating traffic on a port."},
	view_type = "table",
	applies_to = "all,container.id,proc.pid,thread.tid,proc.name",
	filter = "fd.type=ipv4 and fd.name!=''",
	use_defaults = true,
	drilldown_target = "LD_top_procs",
	columns = 
	{
		{
			name = "NA",
			field = "fd.sport",
			is_key = true
		},
		{
			name = "SPORT",
			description = "Server Port.",
			field = "fd.sport",
			colsize = 8,
		},
		{
			name = "BYTES IN",
			field = "evt.buflen.net.in",
			description = "Amount of bytes received by the process owning the socket.",
			is_sorting = true,
			colsize = 12,
			aggregation = "SUM"
		},
		{
			name = "BYTES OUT",
			field = "evt.buflen.net.out",
			description = "amount of bytes sent by the process owning the socket.",
			colsize = 12,
			aggregation = "SUM"
		},
		{
			name = "IO CALLS",
			field = "evt.count",
			description = "Total (read+write) number of input/output calls made by the process on the connection.",
			colsize = 12,
			aggregation = "SUM"
		}
--		,{
--			name = "Container",
--			field = "container.name",
--			colsize = 15
--		}
	}
}
