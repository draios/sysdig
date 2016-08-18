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
description = "Converts sysdig span duration data into statsd metrics and pipes them to the given statsd server. See https://github.com/draios/sysdig/wiki/Tracers for more information.";
short_description = "Export spans duration as statds metrics.";
category = "Tracers";

args =
{
	{
		name = "server_addr",
		description = "The address of the statsd server to send data to",
		argtype = "string",
		optional = true
	},
	{
		name = "server_port",
		description = "The UDP port to use",
		argtype = "string",
		optional = true
	},
}

local lstatsd = require "statsd"
local host = "127.0.0.1"
local port = 8125

-- Argument notification callback
function on_set_arg(name, val)
	if name == "server_addr" then
		host = val
		return true
	elseif name == "server_port" then
		port = tonumber(val)
		return true
	end

	return false
end

-- Initialization callback
function on_init()
	-- Initialize statsd
	statsd = lstatsd({host = "127.0.0.1"})

	-- Request the fields that we need
	ftags = chisel.request_field("span.tags")
	flatency = chisel.request_field("span.duration")
	
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
