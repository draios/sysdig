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
description = "Shows the network payloads exchanged using a given IP port number. You can combine this chisel with the -x, -X or -A sysdig command line switches to customize the screen output";
short_description = "Show the data exchanged using the given IP port number";
category = "Net";

-- Chisel argument list
args = 
{
	{
		name = "host_port",
		description = "The remote host IP port number", 
		argtype = "int"
	},
	{
		   name = "disable_color",
		   description = "Set to 'disable_colors' if you want to disable color output",
		   argtype = "string",
		   optional = true
	},
}

require "common"
terminal = require "ansiterminal"
terminal.enable_color(true)

-- Argument notification callback
function on_set_arg(name, val)
    if name == "host_port" then
        port = val
        return true
    elseif name == "disable_color" then
        if val == "disable_colors" then
            terminal.enable_color(false)
        end
        return true
    end
    return false
end

-- Initialization callback
function on_init()
	-- Request the fields that we need
	fdata = chisel.request_field("evt.arg.data")
	fisread = chisel.request_field("evt.is_io_read")
	fres = chisel.request_field("evt.rawarg.res")

	-- increase the snaplen so we capture more of the conversation 
	sysdig.set_snaplen(1000)

	-- set the filter
        chisel.set_filter("evt.is_io=true and fd.type=ipv4 and fd.port=" .. port )
	return true
end

DIR_READ = 1
DIR_WRITE = 2

direction = nil

-- Event parsing callback
function on_event()
	res = evt.field(fres)
	data = evt.field(fdata)
	
	if res == nil or res <= 0 then
		return true
	end

	if data ~= nil then
		isread = evt.field(fisread)	
		
		if isread and direction ~= DIR_READ then
			infostr = string.format("%s------ Read %s", terminal.red, format_bytes(res))
			direction = DIR_READ
		elseif not isread and direction ~= DIR_WRITE then
			infostr = string.format("%s------ Read %s", terminal.blue, format_bytes(res))
			direction = DIR_WRITE
		end

		print(infostr)
		print(data)
	end

	return true
end

function on_capture_end()
	print(terminal.reset)
end
