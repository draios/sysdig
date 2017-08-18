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

-- Imports and globals
require "common"

-- Chisel argument list
args = {}

local g_disable_index = true	-- change this if you are working on this script and 
							  	-- don't want to be bothered by indexing
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
	s.newConnectionsO = create_category_basic()
	s.newConnectionsI = create_category_basic()
	s.newListeningPorts = create_category_basic()
	s.fileDeletionsCount = create_category_basic()
	s.newSymLinksCount = create_category_basic()
	s.forkCount = create_category_basic()
	s.openErrorCount = create_category_basic()
	s.connectErrorCount = create_category_basic()
	s.sudoInvocations = create_category_basic()
	s.setnsInvocations = create_category_basic()
	s.signalCount = create_category_basic()
	s.segfaultCount = create_category_basic()
	s.over1msFileIoCount = create_category_basic()
	s.over10msFileIoCount = create_category_basic()
	s.over100msFileIoCount = create_category_basic()
	s.appLogCount = create_category_basic()
	s.appLogCountW = create_category_basic()
	s.appLogCountE = create_category_basic()
	s.sysLogCount = create_category_basic()
	s.sysLogCountW = create_category_basic()
	s.sysLogCountE = create_category_basic()
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
				dt[tk] = tv
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

function is_log_file(filename)
	if(string.find(filename, '.log') or
		string.find(filename, '_log') or
		string.find(filename, '/var/log')) and
		not (string.find(filename, '.gz') or string.find(filename, '.tgz'))
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

	local ttable = sysdig.get_thread_table(sysdig.get_filter())

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
	local ttable = sysdig.get_thread_table_nofds(sysdig.get_filter())

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
		data[v.id] = v.name
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
	fbuffer = chisel.request_field("evt.buffer")
	fbuflen = chisel.request_field("evt.buflen")
	fsport = chisel.request_field("fd.sport")
	flport = chisel.request_field("fd.lport")
	ftypechar = chisel.request_field("fd.typechar")
	fexe = chisel.request_field("evt.arg.exe")
	fsignal = chisel.request_field("evt.arg.sig")
	flatency = chisel.request_field("evt.latency")
	fsyslogsev = chisel.request_field("syslog.severity")

	print('{"slices": [')
	return true
end

function on_capture_start()
	if not g_disable_index then
		local dirname = sysdig.get_evtsource_name() .. '_wd_index'
		local f = io.open(dirname .. '/summary.json', "r")
		if f ~= nil then
			f:close()
			file_cache_exists = true
			sysdig.end_capture()
		end
	end

	parse_thread_table_startup()
	return true
end

-------------------------------------------------------------------------------
-- Event callback
-------------------------------------------------------------------------------
function on_event()
	local dir = evt.field(fdir)

	if dir ~= nil then
		if dir == '<' then
			local rawres = evt.field(frawres)
			local etype = evt.field(fetype)

			if rawres ~= nil and rawres >= 0 then
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

							-- log metrics support

							local syslogsev = evt.field(fsyslogsev)
							if syslogsev ~= nil then
								ssummary.sysLogCount.tot = ssummary.sysLogCount.tot + 1
								if syslogsev == 4 then
									ssummary.sysLogCountW.tot = ssummary.sysLogCountW.tot + 1
								elseif syslogsev < 4 then
									ssummary.sysLogCountE.tot = ssummary.sysLogCountE.tot + 1
								end
							elseif is_log_file(fdname) then
								local buf = evt.field(fbuffer)
								local msgs = split(buf, "\n")

								for i, msg in ipairs(msgs) do
									if #msg ~= 0 then
										ssummary.appLogCount.tot = ssummary.appLogCount.tot + 1

										local ls = string.lower(msg)
										
										if string.find(ls, "warn") ~= nil then
											ssummary.appLogCountW.tot = ssummary.appLogCountW.tot + 1
										elseif string.find(msg, "err") or string.find(msg, "critic") or string.find(msg, "emergency") or string.find(msg, "alert") then
											ssummary.appLogCountE.tot = ssummary.appLogCountE.tot + 1
										end
									end
								end
							end
						elseif isread then
							ssummary.fileBytes.tot = ssummary.fileBytes.tot + buflen
							ssummary.fileBytesR.tot = ssummary.fileBytesR.tot + buflen
						end

						local latency = evt.field(flatency)
						if latency ~= nil and not string.starts(fdname, '/dev/') then
							if latency > 100000000 then
								ssummary.over100msFileIoCount.tot = ssummary.over100msFileIoCount.tot + 1
							end
							if latency > 10000000 then
								ssummary.over10msFileIoCount.tot = ssummary.over10msFileIoCount.tot + 1
							end
							if latency > 1000000 then
								ssummary.over1msFileIoCount.tot = ssummary.over1msFileIoCount.tot + 1
							end
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
					elseif fdtype == 'unix' then
						if iswrite then
							-- apps can write to syslog using unix pipes
							local syslogsev = evt.field(fsyslogsev)
							if syslogsev ~= nil then
								ssummary.sysLogCount.tot = ssummary.sysLogCount.tot + 1
								if syslogsev == 4 then
									ssummary.sysLogCountW.tot = ssummary.sysLogCountW.tot + 1
								elseif syslogsev < 4 then
									ssummary.sysLogCountE.tot = ssummary.sysLogCountE.tot + 1
								end
							end
						end
					end
				elseif etype == 'execve' then
					ssummary.SpawnedProcs.tot = ssummary.SpawnedProcs.tot + 1

					local exe = evt.field(fexe)
					if exe == 'sudo' then
						ssummary.sudoInvocations.tot = ssummary.sudoInvocations.tot + 1
					end
				elseif etype == 'bind' then
					local sport = evt.field(fsport)
					if sport ~= nil then
						generate_io_stats(sport, ssummary.listeningPortCount)
						ssummary.newListeningPorts.tot = ssummary.newListeningPorts.tot + 1
					end
				elseif etype == 'connect' then
					local sport = evt.field(fsport)
					if sport ~= nil then
						ssummary.newConnectionsO.tot = ssummary.newConnectionsO.tot + 1
					end
				elseif etype == 'accept' then
					local sport = evt.field(fsport)
					if sport ~= nil then
						ssummary.newConnectionsI.tot = ssummary.newConnectionsI.tot + 1
					end
				elseif etype == 'unlink' or etype == 'unlinkat' then
					ssummary.fileDeletionsCount.tot = ssummary.fileDeletionsCount.tot + 1
				elseif etype == 'symlink' or etype == 'symlinkat' then
					ssummary.newSymLinksCount.tot = ssummary.newSymLinksCount.tot + 1
				elseif etype == 'clone' or etype == 'fork' then
					if rawres > 0 then
						ssummary.forkCount.tot = ssummary.forkCount.tot + 1
					end
				elseif etype == 'setns' then
					ssummary.setnsInvocations.tot = ssummary.setnsInvocations.tot + 1
				end
			elseif etype == 'connect' then
				local sport = evt.field(fsport)
				if sport ~= nil then
					ssummary.newConnectionsO.tot = ssummary.newConnectionsO.tot + 1
				end

				if rawres ~= -115 then
					local fdtype = evt.field(ffdtype)
					if fdtype == 'ipv4' or fdtype == 'ipv6' then
						ssummary.connectErrorCount.tot = ssummary.connectErrorCount.tot + 1
					end
				end
			elseif etype == 'accept' then
				local sport = evt.field(fsport)
				if sport ~= nil then
					ssummary.newConnectionsI.tot = ssummary.newConnectionsI.tot + 1
				end
			elseif etype == 'open' then
				ssummary.openErrorCount.tot = ssummary.openErrorCount.tot + 1
			end
		else	
			local etype = evt.field(fetype)
			if etype == 'close' then
				local sport = evt.field(fsport)
				if sport ~= nil then
					local typechar = evt.field(ftypechar)
					if typechar == '2' then
						if ssummary.listeningPortCount.table[sport] ~= nil then
							ssummary.listeningPortCount.table[sport] = nil
							ssummary.listeningPortCount.tot = ssummary.listeningPortCount.tot - 1
						end
					end
				end
			elseif etype == 'signaldeliver' then
				ssummary.signalCount.tot = ssummary.signalCount.tot + 1
				local signal = evt.field(fsignal)
				if signal == 'SIGSEGV' then
					ssummary.segfaultCount.tot = ssummary.segfaultCount.tot + 1
				end
			elseif etype == 'notification' then
				ssummary.notifications.tot = ssummary.notifications.tot + 1
			end
		end
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
	local ctable = copytable(gsummary.containerCount.table)
	local res = {}
	local jtable = {info={containers=ctable}, metrics=res}

	update_table_counts()

	res[#res+1] = {
		name = 'Sysdig Secure Notifications',
		desc = 'Sysdig Secure notifications. Sysdig secure inserts a "notification" event in the capture stream each time a policy triggers. This metric counts the notifications. Chart it over time to compare the other metrics with the point in time where policies were triggered.',
		category = 'General',
		targetView = 'notifications',
		data = gsummary.notifications
	}

	res[#res+1] = {
		name = 'Running Processes',
		desc = 'Total number of processes that were running during the capture',
		category = 'General',
		targetView = 'procs',
		data = gsummary.procCount
	}

	res[#res+1] = {
		name = 'Running Containers',
		desc = 'Total number of containers that were running during the capture',
		category = 'General',
		targetView = 'containers',
		data = gsummary.containerCount
	}

	res[#res+1] = {
		name = 'File Bytes In+Out',
		desc = 'Amount of bytes read from or written to the file system',
		category = 'File',
		targetView = 'files',
		targetViewSortingCol = 2,
		data = gsummary.fileBytes
	}

	res[#res+1] = {
		name = 'File Bytes In',
		desc = 'Amount of bytes read from the file system',
		category = 'File',
		targetView = 'files',
		targetViewSortingCol = 0,
		data = gsummary.fileBytesR
	}

	res[#res+1] = {
		name = 'File Bytes Out',
		desc = 'Amount of bytes written to the file system',
		category = 'File',
		targetView = 'files',
		targetViewSortingCol = 1,
		data = gsummary.fileBytesW
	}

	res[#res+1] = {
		name = 'Accessed Files',
		desc = 'Number of files that have been accessed during the capture',
		category = 'File',
		targetView = 'files',
		targetViewSortingCol = 2,
		data = gsummary.fileCount
	}

	res[#res+1] = {
		name = 'Modified Files',
		desc = 'Number of files that have been accessed during the capture',
		category = 'File',
		targetView = 'files',
		targetViewSortingCol = 1,
		targetViewFilter = 'evt.is_io_write=true',
		data = gsummary.fileCountW
	}

	res[#res+1] = {
		name = 'Modified System Files',
		desc = 'Number of files that have been accessed during the capture',
		category = 'Security',
		targetViewSortingCol = 1,
		targetView = 'files',
		targetViewFilter = 'evt.is_io_write=true',
		data = gsummary.sysFileCountW
	}

	res[#res+1] = {
		name = 'Active Network Connections',
		desc = 'Number of network connections that have been accessed during the capture',
		category = 'Network',
		targetView = 'connections',
		targetViewSortingCol = 8,
		data = gsummary.connectionCount
	}

	res[#res+1] = {
		name = 'Net Bytes In+Out',
		desc = 'Amount of bytes read from or written to the network',
		category = 'Network',
		targetView = 'sports',
		targetViewSortingCol = 4,
		data = gsummary.netBytes
	}

	res[#res+1] = {
		name = 'Net Bytes In',
		desc = 'Amount of bytes read from the network',
		category = 'Network',
		targetView = 'sports',
		targetViewSortingCol = 2,
		data = gsummary.netBytesR
	}

	res[#res+1] = {
		name = 'Net Bytes Out',
		desc = 'Amount of bytes written to the network',
		category = 'Network',
		targetView = 'sports',
		targetViewSortingCol = 3,
		data = gsummary.netBytesW
	}

	res[#res+1] = {
		name = 'Executed Commands',
		desc = 'Number of new programs that have been executed during the observed interval',
		category = 'Security',
		targetView = 'spy_users',
		data = gsummary.SpawnedProcs
	}

	res[#res+1] = {
		name = 'Listening Ports',
		desc = 'Number of open ports on this system',
		category = 'Network',
		targetView = 'port_bindings',
		data = gsummary.listeningPortCount
	}

	res[#res+1] = {
		name = 'New Listening Ports',
		desc = 'Number of open ports that have been added during the observation interval',
		category = 'Network',
		targetView = 'port_bindings',
		data = gsummary.newListeningPorts
	}

	res[#res+1] = {
		name = 'New Outbound Connections',
		desc = 'New client network connections',
		category = 'Network',
		targetView = 'dig',
		targetViewTitle = 'Connect events',
		targetViewFilter = 'evt.type=connect and evt.dir=< and fd.sport exists',
		data = gsummary.newConnectionsO
	}

	res[#res+1] = {
		name = 'New Inbound Connections',
		desc = 'New server network connections',
		category = 'Network',
		targetView = 'dig',
		targetViewTitle = 'Connect events',
		targetViewFilter = 'evt.type=accept and evt.dir=< and fd.sport exists',
		data = gsummary.newConnectionsI
	}

	res[#res+1] = {
		name = 'Deleted Files',
		desc = 'Number of files that were deleted',
		category = 'File',
		targetView = 'dig',
		targetViewTitle = 'File deletions',
		targetViewFilter = 'evt.type=unlink or evt.type=unlinkat',
		data = gsummary.fileDeletionsCount
	}

	res[#res+1] = {
		name = 'New Symlinks',
		desc = 'Number of new symbolic links that were created',
		category = 'Security',
		targetView = 'dig',
		targetViewTitle = 'Symlink creations',
		targetViewFilter = '(evt.type=symlink or evt.type=symlinkat) and evt.dir=< and evt.failed = false',
		data = gsummary.newSymLinksCount
	}

	res[#res+1] = {
		name = 'Fork Count',
		desc = 'Count of processes and threads that have been created',
		category = 'Performance',
		targetView = 'dig',
		targetViewTitle = 'Clone executions',
		targetViewFilter = 'evt.type=clone and evt.rawres=0',
		data = gsummary.forkCount
	}

	res[#res+1] = {
		name = 'File Open Errors',
		desc = 'Count of failed file opens',
		category = 'Performance',
		targetView = 'dig',
		targetViewTitle = 'Failed open() calls',
		targetViewFilter = 'evt.type=open and evt.rawres<0',
		data = gsummary.openErrorCount
	}

	res[#res+1] = {
		name = 'Failed Connection Attempts',
		desc = 'Count of failed network connect calls',
		category = 'Performance',
		targetView = 'dig',
		targetViewTitle = 'Failed connect() calls',
		targetViewFilter = 'evt.type=connect and (fd.type=ipv4 or fd.type=ipv6) and evt.rawres<0 and evt.res!=EINPROGRESS',
		data = gsummary.connectErrorCount
	}

	res[#res+1] = {
		name = 'Sudo Invocations',
		desc = 'Number of times the sudo program has been called',
		category = 'security',
		targetView = 'dig',
		targetViewTitle = 'Sudo executions',
		targetViewFilter = 'evt.type=execve and evt.arg.exe=sudo',
		data = gsummary.sudoInvocations
	}

	res[#res+1] = {
		name = 'Setns Invocations',
		desc = 'Number of times the setns system call has been called. Setns is typically used to "enter" in another container',
		category = 'security',
		targetView = 'dig',
		targetViewTitle = 'Setns executions',
		targetViewFilter = 'evt.type=setns',
		data = gsummary.setnsInvocations
	}

	res[#res+1] = {
		name = 'Received Signals',
		desc = 'Number of unix signals that have been received by the processes on the system',
		category = 'performance',
		targetView = 'dig',
		targetViewTitle = 'Received signals',
		targetViewFilter = 'evt.type=signaldeliver',
		data = gsummary.signalCount
	}

	res[#res+1] = {
		name = 'Segmentation Faults',
		desc = 'Number of process segfaults',
		category = 'performance',
		targetView = 'dig',
		targetViewTitle = 'List of segfault events',
		targetViewFilter = 'evt.type=signaldeliver and evt.arg.sig=SIGSEV',
		data = gsummary.segfaultCount
	}

	res[#res+1] = {
		name = 'Slow File I/O calls (1ms+)',
		desc = 'Number of file read or write calls that took more than 1ms to return',
		category = 'performance',
		targetView = 'slow_io',
		targetViewSortingCol = 1,
		data = gsummary.over1msFileIoCount
	}

	res[#res+1] = {
		name = 'Slow File I/O calls (10ms+)',
		desc = 'Number of file read or write calls that took more than 10ms to return',
		category = 'performance',
		targetView = 'slow_io',
		targetViewSortingCol = 1,
		data = gsummary.over10msFileIoCount
	}

	res[#res+1] = {
		name = 'Slow File I/O calls (100ms+)',
		desc = 'Number of file read or write calls that took more than 100ms to return',
		category = 'performance',
		targetView = 'slow_io',
		targetViewSortingCol = 1,
		data = gsummary.over100msFileIoCount
	}

	res[#res+1] = {
		name = 'App Log Messages',
		desc = 'Number of wrtites to application log files',
		category = 'logs',
		targetView = 'echo',
		targetViewTitle = 'Application Log Messages',
		targetViewFilter = '((fd.name contains .log or fd.name contains _log or fd.name contains /var/log) and not (fd.name contains .gz or fd.name contains .tgz)) and evt.is_io_write=true',
		data = gsummary.appLogCount
	}

	res[#res+1] = {
		name = 'App Log Warning Messages',
		desc = 'Number of writes to application log files containing the word "warning"',
		category = 'logs',
		targetView = 'echo',
		targetViewTitle = 'Warning Application Log Messages',
		targetViewFilter = '((fd.name contains .log or fd.name contains _log or fd.name contains /var/log) and not (fd.name contains .gz or fd.name contains .tgz)) and evt.is_io_write=true and evt.buffer contains arning',
		data = gsummary.appLogCountW
	}

	res[#res+1] = {
		name = 'App Log Error Messages',
		desc = 'Number of writes to application log files containing the word "error"',
		category = 'logs',
		targetView = 'echo',
		targetViewTitle = 'Error Application Log Messages',
		targetViewFilter = '((fd.name contains .log or fd.name contains _log or fd.name contains /var/log) and not (fd.name contains .gz or fd.name contains .tgz)) and evt.is_io_write=true and (evt.buffer contains rror or evt.buffer contains ritic or evt.buffer ergency rror or evt.buffer contains lert)',
		data = gsummary.appLogCountE
	}

	res[#res+1] = {
		name = 'Syslog Messages',
		desc = 'Number of entries written to syslog',
		category = 'logs',
		targetView = 'spy_syslog',
		targetViewTitle = 'Syslog Messages',
--		targetViewFilter = '((fd.name contains .log or fd.name contains _log or fd.name contains /var/log) and not (fd.name contains .gz or fd.name contains .tgz)) and evt.is_io_write=true',
		data = gsummary.sysLogCount
	}

	res[#res+1] = {
		name = 'Syslog Warning Messages',
		desc = 'Number of entries with severity WARNING written to syslog',
		category = 'logs',
		targetView = 'spy_syslog',
		targetViewTitle = 'Syslog Messages',
		targetViewFilter = 'syslog.severity=4',
		data = gsummary.sysLogCountW
	}

	res[#res+1] = {
		name = 'Syslog Error Messages',
		desc = 'Number of entries with severity ERROR or lower written to syslog',
		category = 'logs',
		targetView = 'spy_syslog',
		targetViewTitle = 'Syslog Messages',
		targetViewFilter = 'syslog.severity<4',
		data = gsummary.sysLogCountE
	}

	resstr = json.encode(jtable, { indent = true })
	return resstr
end

-- Callback called by the engine at the end of the capture
function on_capture_end(ts_s, ts_ns, delta)
	local sstr = ''
	local dirname = sysdig.get_evtsource_name() .. '_wd_index'

	if file_cache_exists and not g_disable_index then
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
		os.execute('rmdir ' .. dirname .. " 2> nul")
		os.execute('mkdir ' .. dirname .. " 2> /dev/null")
		os.execute('md ' .. dirname .. " 2> nul")

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
