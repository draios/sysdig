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

-- Chisel description
description = "lists every command that users launch interactively (e.g. from bash) and every directory users visit";
short_description = "Display interactive user activity";
category = "Security";

-- Chisel argument list
args = {}

-- Initialization callback
function on_init()
	-- Request the fields that we need
	fetype = chisel.request_field("evt.type")
	fexe = chisel.request_field("proc.exe")
	fargs = chisel.request_field("proc.args")
	fdir = chisel.request_field("evt.arg.path")
	fuser = chisel.request_field("user.name")

	-- set the filter
	chisel.set_filter("(evt.type=execve and not proc.name contains sh and proc.pname contains sh) or (evt.type=chdir and evt.dir=< and proc.name contains sh and not proc.name contains sshd)")
	
	return true
end

-- Event parsing callback
function on_event()
	local user = evt.field(fuser)
	if user == nil then
		user = "<NA>"
	end
	
	if evt.field(fetype) == "chdir" then
		print(user .. ")" .. "cd " .. evt.field(fdir))
	else
		print(user .. ")" .. evt.field(fexe) .. " " .. evt.field(fargs))
	end

	return true
end
