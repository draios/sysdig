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
description = "XXX";
short_description = "Sysdig marker flame graph builder";
category = "Performance";

-- Chisel argument list
args =
{
}

require "common"
json = require ("dkjson")

local markers = {}
local flatency = nil
local fcontname = nil
local MAX_DEPTH = 256
local data = {}

-- Argument notification callback
function on_set_arg(name, val)
	return true
end

-- Initialization callback
function on_init()
	-- Request the fields needed for this chisel
	for j = 0, MAX_DEPTH do
		local fname = "marker.tag[" .. j .. "]"
		local minfo = chisel.request_field(fname)
		markers[j] = minfo
	end
	
	flatency = chisel.request_field("marker.latency")
	fcontname = chisel.request_field("container.name")

	-- set the filter
	chisel.set_filter("evt.type=marker and evt.dir=<")

	return true
end

-- Event parsing callback
function on_event()
	local mrk_cur = data
	local latency = evt.field(flatency)
	local contname = evt.field(fcontname)
	local hr = {}
	
	if latency == nil then
		return true
	end

	for j = 0, MAX_DEPTH do
		hr[j + 1] = evt.field(markers[j])
	end

	--print(st(hr))

	for j = 1, #hr do
		local mv = hr[j]
		
		if mv == nil then
			break
		end
		
		if j == #hr then
			if mrk_cur[mv] == nil then
				mrk_cur[mv] = {svUnique=latency, svTotal=0, cont=contname}
			else
				mrk_cur[mv]["svUnique"] = mrk_cur[mv]["svUnique"] + latency
				mrk_cur[mv]["cont"] = contname
			end
		elseif j == (#hr - 1) then
			if mrk_cur[mv] == nil then
				mrk_cur[mv] = {svUnique=-latency, svTotal=0}
			else
				mrk_cur[mv]["svUnique"] = mrk_cur[mv]["svUnique"] - latency
			end
		else
			if mrk_cur[mv] == nil then
				mrk_cur[mv] = {svUnique=0, svTotal=0}
			end
		end
		
		--print(mv)
		--print(st(mrk_cur))
		
		if mrk_cur[mv]["svChildren"] == nil then
			mrk_cur[mv]["svChildren"] = {}
		end
		
		mrk_cur = mrk_cur[mv]["svChildren"]
	end

	--print(st(data))
	
	return true
end

-- Called by the engine at the end of the capture (Ctrl-C)
function on_capture_end()
	local FGData = {}
	FGData[""] = {svChildren=data, svUnique=0, svTotal=0}
	local str = json.encode(FGData, { indent = true })
	print("FGData = " .. str .. ";")
end
