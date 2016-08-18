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
description = "This console visualization shows the frequency of system call latencies. The Y axis unit is time. By default, a new line is created twice a second, but that can be changed by specifying a different refresh time argument. The X axis shows a range of latencies. Each latency value has a color that can be black (no calls), green (tens of calls/s), yellow (hundreds of calls/s) or red (Thousands of calls/s). In other words, red areas mean that there are many system calls taking the specified time to return. Use this chisel in conjunction with filters to visualize latencies for certain processes, types of I/O activity, file systems, etc."
short_description = "Visualize OS latency in real time."
category = "CPU Usage"

-- Chisel argument list
args = {
	{
		name = "refresh_time",
		description = "Chart refresh time in milliseconds",
		argtype = "int",
		optional = true
	},
}

require "common"
terminal = require "ansiterminal"
terminal.enable_color(true)

refresh_time = 500000000
refresh_per_sec = 1000000000 / refresh_time
frequencies = {}
colpalette = {22, 28, 64, 34, 2, 76, 46, 118, 154, 191, 227, 226, 11, 220, 209, 208, 202, 197, 9, 1}

-- Argument initialization Callback
function on_set_arg(name, val)
	if name == "refresh_time" then
		refresh_time = parse_numeric_input(val, name) * 1000000
		refresh_per_sec = 1000000000 / refresh_time
		return true
	end

	return false
end

-- Initialization callback
function on_init()
	is_tty = sysdig.is_tty()

	if not is_tty then
		print("This chisel only works on ANSI terminals. Aborting.")
		return false
	end

	tinfo = sysdig.get_terminal_info()
	w = tinfo.width
	h = tinfo.height

	chisel.set_filter("evt.dir=<")

	flatency = chisel.request_field("evt.latency")

	terminal.hidecursor()

	return true
end

-- Final chisel initialization
function on_capture_start()
	chisel.set_interval_ns(refresh_time)
	return true
end

-- Event parsing callback
function on_event()
	local latency = evt.field(flatency)

	if latency == 0 then
		return true
	end

	local llatency = math.log10(latency)

	if(llatency > 11) then
		llatency = 11
	end

	local norm_llatency = math.floor(llatency * w / 11) + 1

	if frequencies[norm_llatency] == nil then
		frequencies[norm_llatency] = 1
	else
		frequencies[norm_llatency] = frequencies[norm_llatency] + 1
	end

	return true
end

function mkcol(n)
	local col = math.floor(math.log10(n * refresh_per_sec + 1) / math.log10(1.6))

	if col < 1 then
		col = 1
	end

	if col > #colpalette then
		col = #colpalette
	end

	return colpalette[col]
end

-- Periodic timeout callback
function on_interval(ts_s, ts_ns, delta)
	terminal.moveup(1)

	for x = 1, w do
		local fr = frequencies[x]
		if fr == nil or fr == 0 then
			terminal.setbgcol(0)
		else
			terminal.setbgcol(mkcol(fr))
		end

		io.write(" ")
	end

	io.write(terminal.reset .. "\n")

	local x = 0
	while true do
		if x >= w then
			break
		end

		local curtime = math.floor(x * 11 / w)
		local prevtime = math.floor((x - 1) * 11 / w)

		if curtime ~= prevtime then
			io.write("|")
			local tstr = format_time_interval(math.pow(10, curtime))
			io.write(tstr)
			x = x + #tstr + 1
		else
			io.write(" ")
			x = x + 1
		end
	end

	io.write("\n")

	frequencies = {}

	return true
end

-- Called by the engine at the end of the capture (Ctrl-C)
function on_capture_end(ts_s, ts_ns, delta)
	if is_tty then
		-- Include the last sample
		on_interval(ts_s, ts_ns, 0)
		
		-- reset the terminal
		print(terminal.reset)
		terminal.showcursor()
	end

	return true
end
