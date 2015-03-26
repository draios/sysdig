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
	id = "LD_file_opens",
	name = "File Opens",
	description = "List file name and process for of all the file opens.",
	tags = {"Default"},
	view_type = "list",
	applies_to = "all,fd.name",
	filter = "evt.type=open and evt.dir=<",
	columns = 
	{
		{
			name = "TIME",
			field = "evt.time",
			colsize = 19,
		},
		{
			name = "FILE",
			field = "fd.name",
			colsize = 40,
		},
		{
			name = "Command",
			field = "proc.exeline",
			colsize = 200,
		}		
	}
}
