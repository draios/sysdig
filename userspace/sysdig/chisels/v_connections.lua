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
	id = "connections",
	name = "Connections",
	description = "Top network connections. This view lists all of the network connections that were active during the last sampling interval, with details for each of them.",
	tips = {"This view can be applied not only to the whole machine, but also to single processes, containers, threads and so on. Use it after a drill down for more fine grained investigation."},
	tags = {"Default"},
	view_type = "table",
	applies_to = {"", "container.id", "proc.pid", "proc.name", "thread.tid", "fd.sport", "fd.sproto", "fd.dport", "fd.dproto", "fd.port", "fd.proto", "fd.lport", "fd.rport", "evt.res", "k8s.pod.id", "k8s.rc.id", "k8s.rs.id", "k8s.svc.id", "k8s.ns.id", "marathon.app.id", "marathon.group.name", "mesos.task.id", "mesos.framework.name"},
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
			name = "LIP",
			description = "Local IP Address.",
			field = "fd.lip",
			colsize = 17,
		},
		{
			name = "LPORT",
			description = "Local Port.",
			field = "fd.lport",
			colsize = 8,
		},
		{
			name = "RIP",
			description = "Remote IP Address.",
			field = "fd.rip",
			colsize = 17,
		},
		{
			name = "RPORT",
			description = "Remote Port.",
			field = "fd.rport",
			colsize = 8,
		},
		{
			name = "PROTO",
			description = "Connection protocol, obtained by resolving the server port name.",
			field = "fd.sproto",
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
			colsize = 20
		},
		{
			name = "Command",
			description = "The full command line of the process owning the connection's socket.",
			field = "proc.exeline",
			aggregation = "MAX",
			colsize = 0
		}
	},
	actions = 
	{
		{
			hotkey = "c",
			command = "tcpdump -niany host %fd.lip and host %fd.rip and port %fd.lport and port %fd.rport",
			description = "tcpdump connection",
		},
		{
			hotkey = "l",
			command = "tcpdump -niany host %fd.lip",
			description = "tcpdump local IP",
		},
		{
			hotkey = "n",
			command = "nslookup %fd.rip",
			description = "nslookup remote IP",
		},
		{
			hotkey = "P",
			command = "ping %fd.rip",
			description = "ping remote IP",
			wait_finish = false
		},
		{
			hotkey = "r",
			command = "tcpdump -niany host %fd.rip",
			description = "tcpdump remot IP",
		},
		{
			hotkey = "t",
			command = "traceroute %fd.rip",
			description = "traceroute remot IP",
		},
	},
}
