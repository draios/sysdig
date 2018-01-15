--[[
Copyright (C) 2017 Draios inc.
 
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
	id = "slow_io",
	name = "Slow File I/O",
	description = "Lists all of the file read and write calls that took more than 1ms to complete, sorted based on completion time.",
	tags = {"Default", "wsysdig"},
	view_type = "table",
	applies_to = {"", "container.id", "proc.pid", "thread.nametid", "thread.tid", "proc.name", "k8s.pod.id", "k8s.rc.id", "k8s.rs.id", "k8s.svc.id", "k8s.ns.id", "marathon.app.id", "marathon.group.name", "mesos.task.id", "mesos.framework.name"},
	filter = "evt.is_io=true and fd.type=file and (not fd.name contains '/dev/') and evt.latency>1000000",
	use_defaults = true,
	columns = 
	{
		{
			name = "NA",
			field = "evt.rawtime",
			is_key = true
		},
		{
			name = "TIME",
			field = "evt.time",
			description = "Time when the command was executed.",
			colsize = 12,
		},
		{
			name = "LATENCY",
			field = "evt.latency",
			description = "The slow file name.",
			is_sorting = true,
			colsize = 8,
		},
		{
			name = "FILENAME",
			field = "fd.name",
			description = "The slow file name.",
			colsize = 32,
		},
		{
			tags = {"containers"},
			name = "Container",
			field = "container.name",
			description = "Name of the container. What this field contains depends on the containerization technology. For example, for docker this is the content of the 'NAMES' column in 'docker ps'",
			colsize = 20
		},
		{
			name = "PID",
			field = "proc.pid",
			description = "PID of the process performing the I/O call.",
			colsize = 12,
		},
		{
			name = "Command",
			field = "proc.exeline",
			aggregation = "MAX",
			description = "The command accessing the slow file, including arguments.",
			colsize = 0
		}		
	}
}
