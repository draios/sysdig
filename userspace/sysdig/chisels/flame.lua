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
description = "Flame graph generator";
short_description = "Sysdig marker flame graph builder";
category = "Performance";

-- Chisel argument list
args =
{
}

require "common"
json = require ("dkjson")

local markers = {}
local fid = nil
local flatency = nil
local fcontname = nil
local fexe = nil
local MAX_DEPTH = 256
local avg_tree = {}
local full_tree = {}

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
	
	fid = chisel.request_field("marker.id")
	flatency = chisel.request_field("marker.latency")
	fcontname = chisel.request_field("container.name")
	fexe = chisel.request_field("proc.exeline")

	-- set the filter
	chisel.set_filter("evt.type=marker and evt.dir=<")

	return true
end

-- This function parses the marker event and upgrades accordingly the given transaction entry
function parse_marker(mrk_cur, hr, latency, contname, exe)
	for j = 1, #hr do
		local mv = hr[j]
		
		if mv == nil then
			break
		end
		
		if j == #hr then
			if mrk_cur[mv] == nil then
				mrk_cur[mv] = {t=latency, tt=latency, cont=contname, exe=exe}
				if j == 1 then
					mrk_cur[mv].n = 0
				end
			else
				mrk_cur[mv]["t"] = mrk_cur[mv]["t"] + latency
				mrk_cur[mv]["tt"] = mrk_cur[mv]["tt"] + latency
				mrk_cur[mv]["cont"] = contname
				mrk_cur[mv]["exe"] = exe
			end
		elseif j == (#hr - 1) then
			if mrk_cur[mv] == nil then
				mrk_cur[mv] = {t=-latency,tt=0}
				if j == 1 then
					mrk_cur[mv].n = 0
				end
			else
				mrk_cur[mv]["t"] = mrk_cur[mv]["t"] - latency
			end
		else
			if mrk_cur[mv] == nil then
				mrk_cur[mv] = {t=0, tt=0}
				if j == 1 then
					mrk_cur[mv].n = 0
				end
			end
		end
		
		--print(mv)
		--print(st(mrk_cur))
		
		if mrk_cur[mv]["ch"] == nil then
			mrk_cur[mv]["ch"] = {}
		end
		
		if #hr == 1 then
			mrk_cur[mv].n = mrk_cur[mv].n + 1
		end

		mrk_cur = mrk_cur[mv]["ch"]
	end		
end

-- Event parsing callback
function on_event()
	local latency = evt.field(flatency)
	local contname = evt.field(fcontname)
	local id = evt.field(fid)
	local exe = evt.field(fexe)
	local hr = {}
	local full_trs = nil

	if latency == nil then
		return true
	end

	for j = 0, MAX_DEPTH do
		hr[j + 1] = evt.field(markers[j])
	end

	--print(st(hr))

	parse_marker(avg_tree, hr, latency, contname, exe)

	if id > 0 then
		if full_tree[id] == nil then
			full_tree[id] = {}
		end

		parse_marker(full_tree[id], hr, latency, contname, exe)
	end

	--print(st(avg_tree))
	
	return true
end

function normalize(node, factor)
	node.t = node.t / factor
	node.tt = node.tt / factor
	if node.ch then
		for k,d in pairs(node.ch) do
			normalize(d, factor)
		end
	end
end

-- Called by the engine at the end of the capture (Ctrl-C)
function on_capture_end()
	-- normalize each root marker tree
	for i,v in pairs(avg_tree) do
		normalize(v, v.n)
	end

	-- emit the average transaction
	local AvgData = {}
	AvgData[""] = {ch=avg_tree, t=0, tt=0}
	local str = json.encode(AvgData, { indent = true })
	print("AvgData = " .. str .. ";")

	-- Locate the best and worst transaction
	local tbest = nil
	local tworst = nil
	local besttime = 1000000000000000
	local worsttime = 0

	for i,v in pairs(full_tree) do
		for key,val in pairs(v) do
			if val.tt > worsttime then
				worsttime = val.tt
				tworst = v
			end

			if val.tt < besttime then
				besttime = val.tt
				tbest = v
			end
		end
	end

	-- emit the best and worst transaction
	local tdata = {}
	tdata[""] = {ch=tbest, t=0, tt=0}
	local str = json.encode(tdata, { indent = true })
	print("MinData = " .. str .. ";")

	local tdata = {}
	tdata[""] = {ch=tworst, t=0, tt=0}
	local str = json.encode(tdata, { indent = true })
	print("MaxData = " .. str .. ";")

--	print(st(full_tree))
end
