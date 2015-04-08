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
	id = "LD_top_cont_conns",
	name = "Top Connections",
	description = "Top Connections with conyainer context.",
	tags = {"Default"},
	view_type = "table",
	applies_to = "all,container.id,proc.pid,thread.tid,proc.name",
	filter = "fd.type=ipv4 and fd.name!=''",
	use_defaults = true,
	columns = 
	{
		{
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
			name = "BYTES IN",
			field = "evt.buflen.net.in",
			description = "Amount of bytes received by the process owning the socket.",
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
		},
		{
			name = "Command",
			description = "The full command line of the process owning the connection's socket.",
			field = "proc.exeline",
			colsize = 200
		}
--		,{
--			name = "Container",
--			field = "container.name",
--			colsize = 15
--		}
	}
}
