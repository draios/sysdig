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
	id = "incoming_connections",
	name = "New Connections",
	description = "List every newly established network connection.",
	tags = {"Default"},
	view_type = "list",
	applies_to = {"", "container.id", "proc.pid", "thread.tid", "proc.name", "fd.name", "fd.containername", "fd.sport", "fd.sproto", "fd.dport", "fd.port", "fd.lport", "fd.rport", "k8s.pod.id", "k8s.rc.id", "k8s.rs.id", "k8s.svc.id", "k8s.ns.id", "marathon.app.id", "marathon.group.name", "mesos.task.id", "mesos.framework.name"},
	filter = "evt.type=accept and evt.dir=< and evt.failed=false",
	columns = 
	{
		{
			name = "TIME",
			field = "evt.time",
			description = "Time when the connection was received by this machine.",
			colsize = 19,
		},
		{
			name = "Connection",
			field = "fd.name",
			description = "Connection tuple details.",
			colsize = 40,
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
			field = "proc.exeline",
			aggregation = "MAX",
			description = "Name and argyuments of the process that received the connection.",
			colsize = 0
		}		
	}
}
