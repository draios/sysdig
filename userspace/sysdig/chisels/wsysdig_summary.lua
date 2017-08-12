--[[
Copyright (C) 2017 Draios inc.

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
description = "internal chisel, creates the json for the wsysdig summary page."
short_description = "wsysdig summary generator"
category = "NA"
hidden = true

-- Chisel argument list
args = {}

local json = require ("dkjson")
local gsummary = {} -- The global summary
local ssummary = {} -- Last sample's summary
local nintervals = 0
local file_cache_exists = false

function on_set_arg(name, val)
	return false
end

-------------------------------------------------------------------------------
-- Summary handling helpers
-------------------------------------------------------------------------------
function create_category_basic()
	return {tot=0, max=0, timeLine={}}
end

function create_category_table()
	return {tot=0, max=0, timeLine={}, table={}}
end

function create_category_global()
	return {tot=0, max=0, timeLine={}, table={}, global=true}
end

function reset_summary(s)
	s.SpawnedProcs = create_category_basic()
	s.procCount = create_category_table()
	s.containerCount = create_category_table()
	s.fileCount = create_category_table()
	s.fileBytes = create_category_basic()
	s.fileBytesR = create_category_basic()
	s.fileBytesW = create_category_basic()
	s.fileCountW = create_category_table()
	s.sysFileCountW = create_category_table()
	s.connectionCount = create_category_table()
	s.netBytes = create_category_basic()
	s.netBytesR = create_category_basic()
	s.netBytesW = create_category_basic()
	s.notifications = create_category_basic()
	if s.listeningPortCount == nil then
		s.listeningPortCount = create_category_table()
	end
end

function add_summaries(ts_s, ts_ns, dst, src)
	local time = sysdig.make_ts(ts_s, ts_ns)

	for k, v in pairs(src) do
		dst[k].tot = dst[k].tot + v.tot
		if v.tot > dst[k].max then
			dst[k].max = v.tot 
		end
		local tl = dst[k].timeLine
		tl[#tl+1] = {t = time, v=v.tot}

		if v.table ~= nil then
			local dt = dst[k].table
			for tk, tv in pairs(v.table) do
				dt[tk] = 1
			end
		end
	end
end

-------------------------------------------------------------------------------
-- Helpers to dig into the data coming from sysdig
-------------------------------------------------------------------------------
function string.starts(big_str, small_str)
   return string.sub(big_str, 1, string.len(small_str)) == small_str
end

function is_system_dir(filename)
	if string.starts(filename, '/bin/') or
		string.starts(filename, '/sbin/') or
		string.starts(filename, '/boot/') or
		string.starts(filename, '/etc/') or
		string.starts(filename, '/lib') or
		string.starts(filename, '/usr/bin/') or
		string.starts(filename, '/usr/sbin/') or
		string.starts(filename, '/usr/share/') or
		string.starts(filename, '/usr/lib')
	then
		return true
	end

	return false
end

function generate_io_stats(fdname, cnt_cat)
	if fdname == nil then
		return
	end

	if cnt_cat.table[fdname] == nil then
		cnt_cat.table[fdname] = 1
		cnt_cat.tot = cnt_cat.tot + 1
	end
end

function parse_thread_table_startup()
	local data = {}
	local cnt = 0

	local ttable = sysdig.get_thread_table()

	for k, v in pairs(ttable) do
		for kf, vf in pairs(v.fdtable) do
			if vf.is_server then
					data[vf.sport] = 1
			end
		end

	end

	ssummary.listeningPortCount.tot = 0
	for k, v in pairs(data) do
		ssummary.listeningPortCount.tot = ssummary.listeningPortCount.tot + 1
	end
--print(ssummary.listeningPortCount.tot)
	ssummary.listeningPortCount.table = data
end

function parse_thread_table_interval()
	local data = {}
	local cnt = 0

	local ttable = sysdig.get_thread_table(false)

	for k, v in pairs(ttable) do
		if v.tid == v.pid then
			data[v.pid] = 1
			cnt = cnt + 1
		end
	end

	ssummary.procCount.tot = cnt
	ssummary.procCount.table = data
end

function parse_container_table()
	local data = {}
	local cnt = 0

	local ctable = sysdig.get_container_table()

	for k, v in pairs(ctable) do
		data[v.id] = 1
		cnt = cnt + 1
	end

	ssummary.containerCount.tot = cnt
	ssummary.containerCount.table = data
end
-------------------------------------------------------------------------------
-- Initialization callbacks
-------------------------------------------------------------------------------
function on_init()	
    chisel.set_interval_ns(100000000)

    reset_summary(gsummary)
    reset_summary(ssummary)

	-- set the following fields on_event()
	fetype = chisel.request_field("evt.type")
	fdir = chisel.request_field("evt.dir")
	frawres = chisel.request_field("evt.rawres")
	ffdname = chisel.request_field("fd.name")
	ffdtype = chisel.request_field("fd.type")
	fiswrite = chisel.request_field("evt.is_io_write")
	fisread = chisel.request_field("evt.is_io_read")
	fbuflen = chisel.request_field("evt.buflen")
	fsport = chisel.request_field("fd.sport")
	flport = chisel.request_field("fd.lport")
--	fcontainername = chisel.request_field("container.name")
--	fcontainerid = chisel.request_field("container.id")

	print('{"slices": [')
	return true
end

function on_capture_start()
--[[
	local dirname = sysdig.get_evtsource_name() .. '_wd_index'
	local f = io.open(dirname .. '/summary.json', "r")
	if f ~= nil then
		f:close()
		file_cache_exists = true
		sysdig.end_capture()
	end
]]--

	parse_thread_table_startup()
	return true
end

-------------------------------------------------------------------------------
-- Event callback
-------------------------------------------------------------------------------
function on_event()
--if true then return end
	local dir = evt.field(fdir)

	if dir ~= nil then
		if dir == '<' then
			local rawres = evt.field(frawres)
			if rawres ~= nil and rawres >= 0 then
				local etype = evt.field(fetype)
				local fdname = evt.field(ffdname)
				local fdtype = evt.field(ffdtype)
				local iswrite = evt.field(fiswrite)
				local isread = evt.field(fisread)

				if iswrite or isread then
					if fdtype == 'file' then
						local buflen = evt.field(fbuflen)
						if buflen == nil then
							buflen = 0
						end
						
						generate_io_stats(fdname, ssummary.fileCount)

						if iswrite then
							generate_io_stats(fdname, ssummary.fileCountW)
							ssummary.fileBytes.tot = ssummary.fileBytes.tot + buflen
							ssummary.fileBytesW.tot = ssummary.fileBytesW.tot + buflen

							if is_system_dir(fdname) then
								generate_io_stats(fdname, ssummary.sysFileCountW)
							end
						elseif isread then
							ssummary.fileBytes.tot = ssummary.fileBytes.tot + buflen
							ssummary.fileBytesR.tot = ssummary.fileBytesR.tot + buflen
						end
					elseif fdtype == 'ipv4' or fdtype == 'ipv6' then
						local buflen = evt.field(fbuflen)
						if buflen == nil then
							buflen = 0
						end

						generate_io_stats(fdname, ssummary.connectionCount)

						if iswrite then
							ssummary.netBytes.tot = ssummary.netBytes.tot + buflen
							ssummary.netBytesW.tot = ssummary.netBytesW.tot + buflen
						elseif isread then
							ssummary.netBytes.tot = ssummary.netBytes.tot + buflen
							ssummary.netBytesR.tot = ssummary.netBytesR.tot + buflen
						end
					end
				elseif etype == 'execve' then
					ssummary.SpawnedProcs.tot = ssummary.SpawnedProcs.tot + 1
				elseif etype == 'bind' then
					local sport = evt.field(fsport)
					generate_io_stats(sport, ssummary.listeningPortCount)
				end
			end
		else	
			local etype = evt.field(fetype)
			if etype == 'close' then
				local sport = evt.field(fsport)
				if sport ~= nil then
					if ssummary.listeningPortCount.table[sport] ~= nil then
						ssummary.listeningPortCount.table[sport] = nil
						ssummary.listeningPortCount.tot = ssummary.listeningPortCount.tot - 1
					end
				end
			end
		end
	end

	if etype == 'notification' then
		ssummary.notifications.tot = ssummary.notifications.tot + 1
	end

	return true
end

-------------------------------------------------------------------------------
-- Periodic timeout callback
-------------------------------------------------------------------------------
function on_interval(ts_s, ts_ns, delta)	
	parse_thread_table_interval()
	parse_container_table()

--print(json.encode(ssummary.listeningPortCount, { indent = true }))
	add_summaries(ts_s, ts_ns, gsummary, ssummary)
	reset_summary(ssummary)

	if nintervals % 20 == 0 then
		print('{"progress": ' .. sysdig.get_read_progress() .. ' },')
		io.flush(stdout)
	end

	nintervals = nintervals + 1

	return true
end

-------------------------------------------------------------------------------
-- End of capture output generation
-------------------------------------------------------------------------------
function update_table_count(cat)
	if cat.table ~= nil then
		local cnt = 0
		for tk, tv in pairs(cat.table) do
			cnt = cnt + 1
		end

		cat.tot = cnt
		cat.table = nil
	end
end

function update_table_counts()
	for k, v in pairs(gsummary) do
		update_table_count(v)
	end
end

function build_output()
	update_table_counts()

	local res = {}

	res[#res+1] = {
		name = 'Sysdig Secure Notifications',
		desc = 'Sysdig Secure notifications. Sysdig secure inserts a "notification" event in the capture stream each time a policy triggers. This metric counts the notifications. Chart it over time to compare the other metrics with the point in time where policies were triggered.',
		targetView = 'notifications',
		data = gsummary.notifications
	}

	res[#res+1] = {
		name = 'Running Processes',
		desc = 'Total number of processes that were running during the capture',
		targetView = 'procs',
		data = gsummary.procCount
	}

	res[#res+1] = {
		name = 'Running Containers',
		desc = 'Total number of containers that were running during the capture',
		targetView = 'containers',
		data = gsummary.containerCount
	}

	res[#res+1] = {
		name = 'File Bytes In+Out',
		desc = 'Amount of bytes read from or written to the file system',
		targetView = 'files',
		targetViewSortingCol = 2,
		data = gsummary.fileBytes
	}

	res[#res+1] = {
		name = 'File Bytes In',
		desc = 'Amount of bytes read from the file system',
		targetView = 'files',
		targetViewSortingCol = 0,
		data = gsummary.fileBytesR
	}

	res[#res+1] = {
		name = 'File Bytes Out',
		desc = 'Amount of bytes written to the file system',
		targetView = 'files',
		targetViewSortingCol = 1,
		data = gsummary.fileBytesW
	}

	res[#res+1] = {
		name = 'Accessed Files',
		desc = 'Number of files that have been accessed during the capture',
		targetView = 'files',
		targetViewSortingCol = 2,
		data = gsummary.fileCount
	}

	res[#res+1] = {
		name = 'Modified Files',
		desc = 'Number of files that have been accessed during the capture',
		targetView = 'files',
		targetViewSortingCol = 1,
		targetViewFilter = 'evt.is_io_write=true',
		data = gsummary.fileCountW
	}

	res[#res+1] = {
		name = 'Modified System Files',
		desc = 'Number of files that have been accessed during the capture',
		targetViewSortingCol = 1,
		targetView = 'files',
		targetViewFilter = 'evt.is_io_write=true',
		data = gsummary.sysFileCountW
	}

	res[#res+1] = {
		name = 'Active Network Connections',
		desc = 'Number of network connections that have been accessed during the capture',
		targetView = 'connections',
		targetViewSortingCol = 8,
		data = gsummary.connectionCount
	}

	res[#res+1] = {
		name = 'Net Bytes In+Out',
		desc = 'Amount of bytes read from or written to the network',
		targetView = 'sports',
		targetViewSortingCol = 4,
		data = gsummary.netBytes
	}

	res[#res+1] = {
		name = 'Net Bytes In',
		desc = 'Amount of bytes read from the network',
		targetView = 'sports',
		targetViewSortingCol = 2,
		data = gsummary.netBytesR
	}

	res[#res+1] = {
		name = 'Net Bytes Out',
		desc = 'Amount of bytes written to the network',
		targetView = 'sports',
		targetViewSortingCol = 3,
		data = gsummary.netBytesW
	}

	res[#res+1] = {
		name = 'Executed Commands',
		desc = 'Number of new programs that have been executed during the observed interval',
		targetView = 'spy_users',
		data = gsummary.SpawnedProcs
	}

	res[#res+1] = {
		name = 'Listening Ports',
		desc = 'Number of new programs that have been executed during the observed interval',
		targetView = 'port_bindings',
		data = gsummary.listeningPortCount
	}

	resstr = json.encode(res, { indent = true })
	return resstr
end

-- Callback called by the engine at the end of the capture
function on_capture_end(ts_s, ts_ns, delta)
	local sstr = ''
	local dirname = sysdig.get_evtsource_name() .. '_wd_index'

--	if file_cache_exists then
if false then
		local f = io.open(dirname .. '/summary.json', "r")
		if f == nil then
			print('{"progress": 100, "error": "can\'t read the trace file index" }')
			print(']}')
			return false
		end

		sstr = f:read("*all")
		f:close()
	else
		add_summaries(ts_s, ts_ns, gsummary, ssummary)
		sstr = build_output()

		os.execute('rm -fr ' .. dirname .. " 2> /dev/null")
		os.execute('mkdir ' .. dirname .. " 2> /dev/null")

		local f = io.open(dirname .. '/summary.json', "w")
		if f == nil then
			print('{"progress": 100, "error": "can\'t create the trace file index" }')
			print(']}')
			return false
		end

		f:write(sstr)
		f:close()
	end

	print('{"progress": 100, "data": '.. sstr ..'}')
	print(']}')

	return true
end
