--[[
Copyright (C) 2013-2015 Draios inc.

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
description = "Show the top process defined by the highest CPU utilization. This chisel is compatible with containers using the sysdig -pc or -pcontainer argument, otherwise no container information will be shown."
short_description = "Top processes by CPU usage"
category = "CPU Usage"

-- Chisel argument list
args = {}

require "common"
terminal = require "ansiterminal"

grtable = {}
islive = false
fkeys = {}
local print_container = false

vizinfo =
{
	key_fld = {"proc.name","proc.pid"},
	key_desc = {"Process", "PID"},
	value_fld = "thread.exectime",
	value_desc = "CPU%",
	value_units = "timepct",
	top_number = 50,
	output_format = "normal"
}

-- Initialization callback
function on_init()
	-- The -pc or -pcontainer options was supplied on the cmd line
	print_container = sysdig.is_print_container_data()

	-- Print container info as well
	if print_container then
		-- Modify host pid column name and add container information
		vizinfo.key_fld = {"proc.name", "proc.pid", "proc.vpid", "container.name"}
		vizinfo.key_desc = {"Process", "Host_pid", "Container_pid", "container.name"}
	end

	-- Request the fields we need
	for i, name in ipairs(vizinfo.key_fld) do
		fkeys[i] = chisel.request_field(name)
	end

	-- Request the fields we need
	fvalue = chisel.request_field(vizinfo.value_fld)
	fcpu = chisel.request_field("thread.cpu")
	
	chisel.set_filter("evt.type=procinfo")

	return true
end

-- Final chisel initialization
function on_capture_start()
	islive = sysdig.is_live()
	vizinfo.output_format = sysdig.get_output_format()

	if islive then
		chisel.set_interval_s(1)
		if vizinfo.output_format ~= "json" then
			terminal.clearscreen()
			terminal.hidecursor()
		end
	end

	return true
end

-- Event parsing callback
function on_event()
	local key = nil
	local kv = nil

	for i, fld in ipairs(fkeys) do
		kv = evt.field(fld)
		if kv == nil then
			return
		end

		if key == nil then
			key = kv
		else
			key = key .. "\001\001" .. evt.field(fld)
		end
	end

	local cpu = evt.field(fcpu)

	if grtable[key] == nil then
		grtable[key] = cpu * 10000000
	else
		grtable[key] = grtable[key] + (cpu * 10000000)
	end

	return true
end

-- Periodic timeout callback
function on_interval(ts_s, ts_ns, delta)
	if vizinfo.output_format ~= "json" then
		terminal.clearscreen()
		terminal.moveto(0, 0)
	end
	
	print_sorted_table(grtable, ts_s, 0, delta, vizinfo)
	
	-- Clear the table
	grtable = {}
	
	return true
end

-- Called by the engine at the end of the capture (Ctrl-C)
function on_capture_end(ts_s, ts_ns, delta)
	if islive and vizinfo.output_format ~= "json" then
		terminal.clearscreen()
		terminal.moveto(0 ,0)
		terminal.showcursor()
		return true
	end
	
	print_sorted_table(grtable, ts_s, 0, delta, vizinfo)
	
	return true
end
