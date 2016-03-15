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
description = "Print the data read and written for any FD. Combine this script with a filter to restrict what it shows. This chisel is compatable with containers using the sysdig -pc or -pcontainer argument, otherwise no container information will be shown. (Blue represents  [Write], and Red represents [Read] for all data except when the -pc or -pcontainer argument is used. If used the container.name and container.id will be represented as: Green [host], and Cyan [container]) Container information will contain '[]' around container.name and container.id.";
short_description = "Print the data read and written by processes.";
category = "I/O";

args =
{
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
local lstatsd = require "statsd"

-- Argument notification callback
function on_set_arg(name, val)
	return true
end

-- Initialization callback
function on_init()
	-- Initialize statsd
	statsd = lstatsd({host = "127.0.0.1"})

	-- Request the fields that we need
	ftags = chisel.request_field("tracer.tags")
	flatency = chisel.request_field("tracer.latency")
	
	-- set the filter
	chisel.set_filter("evt.type=tracer and evt.dir=<")
	return true
end

-- Event parsing callback
function on_event()
	local tags = evt.field(ftags)
	local latency = evt.field(flatency)

	if latency then
		statsd:timer(tags, tonumber(latency) / 1000000)
	end

	return true
end

-- Called by the engine at the end of the capture (Ctrl-C)
function on_capture_end()
end
