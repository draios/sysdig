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
description = "Given two filter fields, a key and a value, this chisel creates and renders a dynamic table to the screen. Where key=container.name and value=thread.exectime (CPU%)"
short_description = "Top containers by CPU usage"
category = "CPU Usage"

-- Chisel argument list
args = {}

require "common"
terminal = require "ansiterminal"

grtable = {}
islive = false
cpustates = {}

vizinfo =
{
	key_fld = "container.name",
	key_desc = {"container.name"},
	value_fld = "thread.exectime",
	value_desc = "CPU%",
	value_units = "timepct",
	top_number = 10,
	output_format = "normal"
}


function on_init()
	-- Request the fields we need
	fkey = chisel.request_field(vizinfo.key_fld)
	fvalue = chisel.request_field(vizinfo.value_fld)
	fnext = chisel.request_field("evt.arg.next")
	fnextraw = chisel.request_field("evt.rawarg.next")

	-- Filter out the host container.name	
	chisel.set_filter("evt.type=switch and container.name!=host")
	
	return true
end

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

	ncpus = sysdig.get_machine_info().num_cpus

	for j = 1, ncpus do
		cpustates[j] = {0, 0, 0, ""}
	end

	return true
end

function on_event()
	key = evt.field(fkey)
	value = evt.field(fvalue)
	cpuid = evt.get_cpuid() + 1

	if key ~= nil and value ~= nil and value > 0 then
		thissec = value - cpustates[cpuid][3]
		if thissec < 0 then
			thissec = 0
		end

		if grtable[key] == nil then
			grtable[key] = thissec
		else
			grtable[key] = grtable[key] + thissec
		end
		
		cpustates[cpuid][1], cpustates[cpuid][2] = evt.get_ts()
	end

	if evt.field(fnext) ~= "" .. evt.field(fnextraw) then
		cpustates[cpuid][4] = evt.field(fnext)
	else
		cpustates[cpuid][4] = nil
	end

	cpustates[cpuid][3] = 0

	return true
end

function on_interval(ts_s, ts_ns, delta)
	if vizinfo.output_format ~= "json" then
		terminal.clearscreen()
		terminal.moveto(0, 0)
	end
	
	for cpuid = 1, ncpus do
		if cpustates[cpuid][1] ~= 0 then
			cpustates[cpuid][3] = 1000000000 - cpustates[cpuid][2]

			key = cpustates[cpuid][4]

			if key ~= nil and value ~= nil and value > 0 then
				if grtable[key] == nil then
					grtable[key] = cpustates[cpuid][3]
				else
					grtable[key] = grtable[key] + cpustates[cpuid][3]
				end
			end
		end
	end
	
	print_sorted_table(grtable, ts_s, 0, delta, vizinfo)
	
	-- Clear the table
	grtable = {}
	
	return true
end

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
