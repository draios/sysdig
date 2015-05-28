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
	id = "connections_cs",
	name = "Connections cs",
	description = "Top network connections. This view lists all of the network connections that were active during the last sampling interval, with details for each of them.",
	tips = {"This view can be applied not only to the whole machine, but also to single processes, containers, threads and so on. Use it after a drill down for more fine grained investigation."},
	tags = {"Default"},
	view_type = "table",
	applies_to = {"", "container.id", "proc.pid", "proc.name", "thread.tid", "fd.sport,evt.res"},
	filter = "fd.type=ipv4 or fd.type=ipv6 and fd.name!=''",
	use_defaults = true,
	drilldown_target = "incoming_connections",
	columns = 
	{
		{
			tags = {"default"},
			name = "NA",
			field = "fd.name",
			is_key = true
		},
		{
			tags = {"containers"},
			name = "NA",
			field = "fd.containername",
			is_key = true
		},
		{
			name = "L4PROTO",
			description = "The connection transport protocol (TCP, UDP, etc.).",
			field = "fd.l4proto",
			colsize = 8,
		},
		{
			name = "CIP",
			description = "Client IP Address.",
			field = "fd.cip",
			colsize = 17,
		},
		{
			name = "CPORT",
			description = "Client Port.",
			field = "fd.cport",
			colsize = 8,
		},
		{
			name = "SIP",
			description = "Server IP Address.",
			field = "fd.sip",
			colsize = 17,
		},
		{
			name = "SPORT",
			description = "Server Port.",
			field = "fd.sport",
			colsize = 8,
		},
		{
			is_sorting = true,
			name = "BPS IN",
			field = "evt.buflen.net.in",
			description = "This connection's input bandwidth in bytes per second.",
			colsize = 12,
			aggregation = "TIME_AVG"
		},
		{
			name = "BPS OUT",
			field = "evt.buflen.net.out",
			description = "This connection's output bandwidth in bytes per second.",
			colsize = 12,
			aggregation = "TIME_AVG"
		},
		{
			name = "IOPS",
			field = "evt.count",
			description = "Total (read+write) number of calls per second made on this connection by the owning process.",
			colsize = 12,
			aggregation = "TIME_AVG"
		},
		{
			tags = {"containers"},
			name = "Container",
			field = "container.name",
			description = "Name of the container. What this field contains depends on the containerization technology. For example, for docker this is the content of the 'NAMES' column in 'docker ps'",
			colsize = 15
		},
		{
			name = "Command",
			description = "The full command line of the process owning the connection's socket.",
			field = "proc.exeline",
			aggregation = "MAX",
			colsize = 200
		}
	}
}
