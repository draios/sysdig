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
	id = "sports",
	name = "Server Ports",
	description = "This view lists all of the server ports in terms of network bandwidth usage.",
	tips = {"Want to restrict this visualization to a single process or container? Just drill down into them before applying it.", 
		"Select a port and drill down with the 'Top Processes' view to see which processes are generating traffic on a port."},
	view_type = "table",
	applies_to = {"", "container.id", "proc.pid", "thread.tid", "proc.name", "evt.res", "k8s.pod.id", "k8s.rc.id", "k8s.rs.id", "k8s.svc.id", "k8s.ns.id", "marathon.app.id", "marathon.group.name", "mesos.task.id", "mesos.framework.name"},
	filter = "fd.type=ipv4 and fd.name!=''",
	use_defaults = true,
	drilldown_target = "connections",
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
			name = "PROTO",
			description = "protocol name, obtained by resolving the port number.",
			field = "fd.sproto",
			colsize = 8,
		},
		{
			name = "BPS IN",
			field = "evt.buflen.net.in",
			description = "This port's input bandwidth in bytes per second.",
			is_sorting = true,
			colsize = 12,
			aggregation = "TIME_AVG"
		},
		{
			name = "BPS OUT",
			field = "evt.buflen.net.out",
			description = "This port's output bandwidth in bytes per second.",
			colsize = 12,
			aggregation = "TIME_AVG"
		},
		{
			name = "IO CALLS",
			field = "evt.count",
			description = "Total (read+write) number of input/output calls made by the process on the connection.",
			colsize = 12,
			aggregation = "SUM"
		}
	},
	actions = 
	{
		{
			hotkey = "t",
			command = "tcpdump -niany port %fd.sport",
			description = "tcpdump port",
			wait_finish = false
		},
	},
}
