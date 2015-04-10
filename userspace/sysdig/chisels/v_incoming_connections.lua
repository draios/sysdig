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
	id = "LD_incoming_connections",
	name = "New Connections",
	description = "List every newly established network connection.",
	tags = {"Default"},
	view_type = "list",
	applies_to = "all,container.id,proc.pid,thread.tid,proc.name,fd.name,fd.containername,fd.sport",
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
			name = "Command",
			field = "proc.exeline",
			description = "Name and argyuments of the process that received the connection.",
			colsize = 200,
		}		
	}
}
