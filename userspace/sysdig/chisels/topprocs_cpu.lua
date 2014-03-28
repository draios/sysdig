--[[

 
This program is free software: you can redistribute it and/or modify




This program is distributed in the hope that it will be useful,





along with this program.  If not, see <http://www.gnu.org/licenses/>.
--]]

-- Chisel description
description = "Given two filter fields, a key and a value, this chisel creates and renders to the screen a table."
short_description = "Top processes by CPU usage"
category = "CPU"

-- Chisel argument list
args = {}

require "common"
terminal = require "ansiterminal"

top_number = 10
grtable = {}
key_fld = "proc.name"
key_desc = "Process"
value_fld = "thread.exectime"
value_desc = "CPU%"
result_rendering = "timepct"
islive = false
cpustates = {}

function on_init()
	-- Request the fields we need
	fkey = chisel.request_field(key_fld)
	fvalue = chisel.request_field(value_fld)
	
	chisel.set_filter("evt.type=switch")
	
	return true
end

function on_capture_start()
	islive = sysdig.is_live()

	if islive then
		chisel.set_interval_s(1)
		terminal.clearscreen()
		terminal.hidecursor()
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
		if grtable[key] == nil then
			grtable[key] = value - cpustates[cpuid][3]
		else
			grtable[key] = grtable[key] + value - cpustates[cpuid][3]
		end
		
		cpustates[cpuid][3] = 0
		
		cpustates[cpuid][1], cpustates[cpuid][2] = evt.get_ts()
		cpustates[cpuid][4] = key
	end

	return true
end

function on_interval(ts_s, ts_ns, delta)
	terminal.clearscreen()
	terminal.goto(0, 0)
	
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
	
	print_sorted_table(grtable, 1000000000, result_rendering)
	
	-- Clear the table
	grtable = {}
	
	return true
end

function on_capture_end(ts_s, ts_ns, delta)
	if islive then
		terminal.clearscreen()
		terminal.goto(0 ,0)
		terminal.showcursor()
		return true
	end
	
	print_sorted_table(grtable, delta, result_rendering)
	
	return true
end

