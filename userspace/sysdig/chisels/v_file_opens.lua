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
	id = "file_opens",
	name = "File Opens List",
	description = "List file name and process for of every single file open.",
	tips = {"The RES column is very useful to identify failed opens. Successful opens will show 'SUCCESS' in this column, while failed opens will show an errno code. Do a 'man errno' to find the meaning of the most important codes. And remember that you can sort the opens based on this code, or filter for specific codes using the F4 key."},
	tags = {"Default"},
	view_type = "list",
	applies_to = {"", "container.id", "proc.pid", "proc.name", "thread.tid", "fd.sport", "fd.sproto", "fd.name", "fd.directory", "evt.res", "k8s.pod.id", "k8s.rc.id", "k8s.rs.id", "k8s.svc.id", "k8s.ns.id", "marathon.app.id", "marathon.group.name", "mesos.task.id", "mesos.framework.name"},
	filter = "evt.type=open and evt.dir=<",
	columns = 
	{
		{
			name = "TIME",
			field = "evt.time",
			description = "The timestamp of the file open.",
			colsize = 19,
		},
		{
			name = "RES",
			field = "evt.res",
			description = "The result of the open call. This can be either 'SUCCESS', or an errno code.",
			colsize = 8,
		},
		{
			name = "FILE",
			field = "fd.name",
			description = "The file name.",
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
			description = "The program that opened the file, including its arguments.",
			colsize = 0,
		}		
	},
	actions = 
	{
		{
			hotkey = "l",
			command = "less %fd.name",
			description = "less file",
			wait_finish = false
		},
	},
}
