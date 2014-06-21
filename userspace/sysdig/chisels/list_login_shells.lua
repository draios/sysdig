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
description = "List the IDs of the login sessions. Optionally, the list can be filtered to include only the sessions that contain a specific command. The session IDs listed by this chisel can be used as filters for the spy_users chisel.";
short_description = "List the login shell IDs";
category = "Security";

args =
{
    {
        name = "command",
        description = "If this parameter is specified, only the login shells that contain commands including the given string in their name will be listed. * will match any command name.",
        argtype = "string",
		optional = true
    },
    {
        name = "arguments",
        description = "If this parameter is specified, only the login shells that contain commands including the given string in their arguments will be listed",
        argtype = "string",
		optional = true
    },
}

require "common"
sids = {}

function on_set_arg(name, val)
	if name == "command" then
		if val ~= "*" then
			matching_comm_str = val
		end
	elseif name == "arguments" then
		matching_arg_str = val
	end
    return true
end

function on_init()
	fsid = chisel.request_field("proc.loginshellid")
	fexe = chisel.request_field("evt.arg.exe")
	fargs = chisel.request_field("evt.arg.args")
	
	chisel.set_filter("evt.type=execve")
		
	return true
end

function on_event()
	sid = evt.field(fsid)
	exe = evt.field(fexe)
	args = evt.field(fargs)
	
	if sid and exe then
		if matching_comm_str and string.find(exe, matching_comm_str) == nil then
			return true
		end
		
		if matching_arg_str and args and string.find(args, matching_arg_str) == nil then
			return true
		end
		
		sids[sid] = 1
	end
	
	return true
end

function on_capture_end()
	if matching_comm_str then
		print("Shells containing " .. matching_comm_str .. ":")
	else
		print("All shells:")
	end
	
	for k, v in pairs(sids) do
		print(k)
	end
end

