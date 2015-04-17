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
	tags = {"Default"},
	view_type = "list",
	applies_to = "all,fd.name",
	filter = "evt.type=open and evt.dir=<",
	columns = 
	{
		{
			name = "TIME",
			field = "evt.num",
			description = "The timestamp of the file open.",
			colsize = 19,
		},
		{
			name = "RES",
			field = "evt.res",
			description = "The result of the open call.",
			colsize = 8,
		},
		{
			name = "FILE",
			field = "fd.name",
			description = "The file name.",
			colsize = 40,
		},
		{
			name = "Command",
			field = "proc.exeline",
			description = "The program that opened the file, including its arguments.",
			colsize = 200,
		}		
	}
}
