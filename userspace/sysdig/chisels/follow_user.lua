--[[

 
This program is free software: you can redistribute it and/or modify




This program is distributed in the hope that it will be useful,





along with this program.  If not, see <http://www.gnu.org/licenses/>.
--]]

-- Chisel description
description = "lists every command that users launches interactively (e.g. from bash) and every directory users visit";
short_description = "display user activity";
category = "Security";

-- Chisel argument list
args = {}

-- Initialization callback
function on_init()
	-- Request the fileds that we need
	fetype = chisel.request_field("evt.type")
	fexe = chisel.request_field("proc.exe")
	fargs = chisel.request_field("proc.args")
	fdir = chisel.request_field("evt.arg.path")
	fuser = chisel.request_field("user.name")

	-- set the filter
	chisel.set_filter("(evt.type=execve and proc.name!=bash and proc.parentname=bash) or (evt.type=chdir and evt.dir=< and proc.name=bash)")
	
	return true
end

-- Event parsing callback
function on_event()
	if evt.field(fetype) == "chdir" then
		print(evt.field(fuser) .. ")" .. "cd " .. evt.field(fdir))
	else
		print(evt.field(fuser) .. ")" .. evt.field(fexe) .. " " .. evt.field(fargs))
	end

	return true
end
