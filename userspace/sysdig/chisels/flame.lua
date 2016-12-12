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
disabled_description = "Flame graph generator";
short_description = "Sysdig trace flame graph builder";
category = "Performance";

-- Chisel argument list
args =
{
}

require "common"
json = require ("dkjson")

local CAPTURE_LOGS = true

local spans = {}
local fid
local flatency
local fcontname
local fexe
local fbuf
local fdir
local ftime
local MAX_DEPTH = 256
local avg_tree = {}
local full_tree = {}
local max_tree = {}
local min_tree = {}
local logs_tree = {}
local next = next -- make next faster

-- Argument notification callback
function on_set_arg(name, val)
	return true
end

-- Initialization callback
function on_init()
	-- Request the fields needed for this chisel
	for j = 0, MAX_DEPTH do
		local fname = "span.tag[" .. j .. "]"
		local minfo = chisel.request_field(fname)
		spans[j] = minfo
	end
	
	fid = chisel.request_field("span.id")
	flatency = chisel.request_field("span.duration")
	fcontname = chisel.request_field("container.name")
	fexe = chisel.request_field("proc.exeline")
	fbuf = chisel.request_field("evt.buffer")
	fdir = chisel.request_field("evt.dir")
	ftid = chisel.request_field("thread.tid")
	ftime = chisel.request_field("evt.time")

	-- set the filter
	if CAPTURE_LOGS then
		chisel.set_filter("(evt.type=tracer) or (evt.is_io_write=true and evt.dir=< and (fd.num=1 or fd.num=2 or fd.name contains log))")
	else
		chisel.set_filter("evt.type=tracer and evt.dir=<")
	end

	return true
end

-- Add a log entry into the proper place(s) in the log table
function collect_log(tid_tree)
	for k,entry in pairs(tid_tree) do
		while true do
			local lastv = v
			k,v = next(entry)
			if v == nil then
				if lastv.l == nil then
					lastv.l = {}
				end

				local etime = evt.field(ftime)
				local buf = evt.field(fbuf)
				local tid = evt.field(ftid)
				local hi, low = evt.get_ts()

				local linedata = {t=etime, th=hi, tl=low, tid=tid, b=buf}

				table.insert(lastv.l, linedata)
--print("*** " .. evt.get_num() .. " " .. linedata)
--print(st(logs_tree))
--print("***************************")
				return
			end

			entry = v.ch
		end
	end
end

-- Parse a tracer enter event and update the logs_tree table
function parse_tracer_enter(logtable_cur, hr)
	for j = 1, #hr do
		local mv = hr[j]
		
		if mv == nil then
			break
		end
		
		if logtable_cur[mv] == nil then
			logtable_cur[mv] = {ch={}}
		end

		if j == #hr then
			logtable_cur[mv].r=true
		end

		logtable_cur = logtable_cur[mv].ch
	end
end

-- Parse a tracer exit event and update the given transaction entry
function parse_tracer_exit(mrk_cur, logtable_cur, hr, latency, contname, exe, id)
	local res = false
	local parent_has_logs = false;

	for j = 1, #hr do
		local mv = hr[j]
		if mv == nil or mrk_cur == nil then
			break
		end
		
		local has_logtable_entry = (logtable_cur ~= nil and logtable_cur[mv] ~= nil)

--print("! " .. evt.get_num() .. " " .. j)
--print(parent_has_logs)
--print(logtable_cur[mv].r)
		if j == #hr then
			local llogs

			if has_logtable_entry and logtable_cur[mv].l ~= nil then
				llogs = logtable_cur[mv].l
			else
				llogs = nil
			end

--print("################ " .. evt.get_num() .. " " .. st(logs_tree))
			if mrk_cur[mv] == nil then
				mrk_cur[mv] = {t=latency, tt=latency, cont=contname, exe=exe, c=1, logs=llogs}
				if j == 1 then
					mrk_cur[mv].n = 0
				end
			else
				mrk_cur[mv]["tt"] = mrk_cur[mv]["tt"] + latency
				mrk_cur[mv]["cont"] = contname
				mrk_cur[mv]["exe"] = exe
				mrk_cur[mv]["c"] = 1
				mrk_cur[mv]["logs"] = llogs
			end

--print("################ " .. evt.get_num())
--print(st(logs_tree))
--print("## " .. evt.get_num())
--print(st(logtable_cur[mv].r))

			if has_logtable_entry and parent_has_logs == false then
				res = true
			else
				logtable_cur[mv] = nil
				has_logtable_entry = false
				logtable_cur = nil
			end
		elseif j == (#hr - 1) then
			if mrk_cur[mv] == nil then
				mrk_cur[mv] = {tt=0}
				if j == 1 then
					mrk_cur[mv].n = 0
				end
			end
		else
			if mrk_cur[mv] == nil then
				mrk_cur[mv] = {tt=0}
				if j == 1 then
					mrk_cur[mv].n = 0
					mrk_cur[mv]["id"] = id
				end
			end
		end
				
		if mrk_cur[mv]["ch"] == nil then
			mrk_cur[mv]["ch"] = {}
		end
		
		if #hr == 1 then
			mrk_cur[mv].n = mrk_cur[mv].n + 1
		end

		-- end of node parsing, update pointers to movo to the child
		if has_logtable_entry then
			parent_has_logs = (logtable_cur[mv].r ~= nil)
		end

		mrk_cur = mrk_cur[mv].ch

		if logtable_cur ~= nil then
			logtable_cur = logtable_cur[mv].ch
		end
	end

	return res
end

-- Event parsing callback
function on_event()
	local etype = evt.get_type()

	if etype ~= "tracer" then
		local tid = evt.field(ftid)

		if logs_tree[tid] == nil then
			return
		else
			collect_log(logs_tree[tid])
		end

		return
	end

	local latency = evt.field(flatency)
	local contname = evt.field(fcontname)
	local id = evt.field(fid)
	local exe = evt.field(fexe)
	local hr = {}
	local full_trs = nil
	local dir = evt.field(fdir)
	local tid = evt.field(ftid)

	for j = 0, MAX_DEPTH do
		hr[j + 1] = evt.field(spans[j])
	end

	if dir == ">" then
		if logs_tree[tid] == nil then
			logs_tree[tid] = {}
		end

		local idt = logs_tree[tid][id]

		if idt == nil then
			logs_tree[tid][id] = {}
			idt = logs_tree[tid][id]			
		end

		parse_tracer_enter(idt, hr)
		return true
	else
		if latency == nil then
			return true
		end

		if full_tree[id] == nil then
			full_tree[id] = {}
		end

		-- find the logs for this transaction span
		local logs

		if logs_tree[tid] == nil then
			logs = nil
		else
			if logs_tree[tid][id] == nil then
				logs = nil
			else
				logs = logs_tree[tid][id]
			end
		end

	if parse_tracer_exit(full_tree[id], logs, hr, latency, contname, exe, id) then
--print(st(logs_tree))
--print("------------ " .. evt.get_num())
--print(st(full_tree))
--print("---------------------------------------------------")

			logs_tree[tid][id] = nil

			if next(logs_tree[tid]) == nil then
				logs_tree[tid] = nil
			end

		end

		return true
	end
end

function calculate_t_in_node(node)
	local totchtime = 0
	local maxchtime = 0
	local nconc = 0
	local ch_to_keep

	if node.ch then
		for k,d in pairs(node.ch) do
			local nv = calculate_t_in_node(d)

			totchtime = totchtime + nv

			if nv > maxchtime then
				maxchtime = nv
				ch_to_keep = d
			end

			nconc = nconc + 1
		end
	end

	if node.tt >= totchtime then
		node.t = node.tt - totchtime
	else
		node.t = node.tt - maxchtime
		node.nconc = nconc

		for k,d in pairs(node.ch) do
			if d ~= ch_to_keep then
				node.ch[k] = nil
			end
		end

	end

	return node.tt
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

function is_transaction_complete(node)
	if node.c ~= 1 then
		return false
	end

	if node.ch then
		for k,d in pairs(node.ch) do
			if is_transaction_complete(d) == false then
				return false
			end
		end
	end

	return true
end

function update_avg_tree(dsttree, key, val)
	if dsttree[key] == nil then
		dsttree[key] = copytable(val)
		return
	else
		dsttree[key].tt = dsttree[key].tt + val.tt

		if dsttree[key].n then
			dsttree[key].n = dsttree[key].n + 1
		end

		if val.logs then
			if dsttree[key].logs == nil then
				dsttree[key].logs = {}
			end

			concattable(dsttree[key].logs, val.logs)
		end
	end

	if val.ch then
		if dsttree[key].ch == nil then
			dsttree[key].ch = {}
		end

		for k,d in pairs(val.ch) do
			update_avg_tree(dsttree[key].ch, k, d)
		end
	end
end

function update_max_tree(dsttree, key, val)
	if dsttree[key] == nil then
		dsttree[key] = val
		return
	else
		if val.tt > dsttree[key].tt then
			dsttree[key] = val
		end
	end
end

function update_min_tree(dsttree, key, val)
	if dsttree[key] == nil then
		dsttree[key] = val
		return
	else
		if val.tt < dsttree[key].tt then
			dsttree[key] = val
		end
	end
end

-- This processes the transaction list to extract and aggregate the transactions to emit
function collapse_tree()
	-- scan the transaction list
	for i,v in pairs(full_tree) do
		local ttt = 0
		for key,val in pairs(v) do
			ttt = ttt + val.tt
			if is_transaction_complete(val) then
				update_avg_tree(avg_tree, key, val)
				update_max_tree(max_tree, key, val)
				update_min_tree(min_tree, key, val)
			end
		end
	end
end

-- Called by the engine at the end of the capture (Ctrl-C)
function on_capture_end()
--print(st(full_tree))
	-- Process the list and create the required transactions
	collapse_tree()

	-- calculate the unique time spent in each node
	for i,v in pairs(avg_tree) do
		calculate_t_in_node(v)
	end

	-- normalize each root span tree
	for i,v in pairs(avg_tree) do
		normalize(v, v.n)
	end

	print "var FlameData = {"

	-- emit the average transaction
	local AvgData = {}
	AvgData[""] = {ch=avg_tree, t=0, tt=0}
	local str = json.encode(AvgData, { indent = true })
	print('"AvgData": ' .. str .. ",")

	-- normalize the best transaction
	for i,v in pairs(min_tree) do
		calculate_t_in_node(v)
	end

	-- emit the best transaction
	local tdata = {}
	tdata[""] = {ch=min_tree, t=0, tt=0}
	local str = json.encode(tdata, { indent = true })
	print('"MinData": ' .. str .. ",")

	-- normalize the worst transaction
	for i,v in pairs(max_tree) do
		calculate_t_in_node(v)
	end

	-- emit the worst transaction
	local tdata = {}
	tdata[""] = {ch=max_tree, t=0, tt=0}
	local str = json.encode(tdata, { indent = true })
	print('"MaxData": ' .. str .. ",")

	print "};"
end
