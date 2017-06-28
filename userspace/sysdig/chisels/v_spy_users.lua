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
	id = "spy_users",
	name = "Spy Users",
	description = "Lists all the commands that are run interactively, i.e. that have a shell as the parent process. The result is the display of all the user activity, sorted by time.",
	tags = {"Default"},
	view_type = "list",
	applies_to = {"", "container.id", "proc.pid", "thread.tid", "proc.name", "k8s.pod.id", "k8s.rc.id", "k8s.rs.id", "k8s.svc.id", "k8s.ns.id", "marathon.app.id", "marathon.group.name", "mesos.task.id", "mesos.framework.name"},
	filter = "((evt.type=execve and evt.dir=<) or (evt.type=chdir and evt.dir=< and proc.name contains sh and not proc.name contains sshd)) and evt.failed=false",
	use_defaults = true,
	columns = 
	{
		{
			name = "TIME",
			field = "evt.time.s",
			description = "Time when the command was executed.",
			colsize = 12,
		},
		{
			name = "USER",
			field = "user.name",
			description = "Name of the user running the command.",
			colsize = 12,
		},
		{
			name = "SHELL",
			field = "proc.ppid",
			description = "Pid of the shell where this command was executed. This, essentially, corresponds to a 'session ID'. You can filer or sort by this column to isolate a specific interactive user session.",
			colsize = 8,
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
			description = "The executed command, including arguments.",
			colsize = 0
		}		
	}
}
