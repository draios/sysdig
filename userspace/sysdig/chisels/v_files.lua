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

view_info = 
{
	id = "files",
	name = "Files",
	description = "This view lists the files that were accessed on the file system. The list can be sorted by metrics like the input/output bytes and the IOPS",
	tips = {"This view can be applied not only to the whole machine, but also to single processes, containers, threads and so on. Use it after a drill down for more fine grained investigation."},
	tags = {"Default"},
	view_type = "table",
	applies_to = {"", "container.id", "proc.pid", "proc.name", "thread.tid", "fd.sport", "fd.sproto", "fd.directory", "fd.containerdirectory", "evt.res", "k8s.pod.id", "k8s.rc.id", "k8s.rs.id", "k8s.svc.id", "k8s.ns.id", "marathon.app.id", "marathon.group.name", "mesos.task.id", "mesos.framework.name"},
	filter = "fd.type=file or fd.type=directory and fd.name!=''",
	use_defaults = true,
	drilldown_target = "procs",
	columns = 
	{
		{
			tags = {"default"},
			name = "NA",
			field = "fd.name",
			is_key = true
		},
		{
			tags = {"containers"},
			name = "NA",
			field = "fd.containername",
			is_key = true
		},
		{
			name = "BYTES IN",
			field = "evt.buflen.file.in",
			description = "Amount of bytes read from the file. For live captures, this is the amount during the last sampling interval. For trace files, this is the total amount for the full file.",
			colsize = 12,
			aggregation = "SUM"
		},
		{
			name = "BYTES OUT",
			field = "evt.buflen.file.out",
			description = "amount of bytes written to the file. For live captures, this is the amount during the last sampling interval. For trace files, this is the total amount for the full file.",
			colsize = 12,
			aggregation = "SUM"
		},
		{
			is_sorting = true,
			name = "OPS",
			field = "evt.count.exit",
			description = "Number of I/O operations on the file. This counts all the operations on the file, including, open, close, read, write, stat, and so on. As a consequence, this value can be nonzero even if I/O bytes for the file are zero.",
			colsize = 9,
			aggregation = "SUM"
		},
		{
			name = "OPENS",
			field = "evt.type.is.3",
			description = "Number times the file has been opened during the sample interval. On trace files, this is the total for the whole file.",
			colsize = 9,
			aggregation = "SUM"
		},
		{
			name = "ERRORS",
			field = "evt.count.error",
			description = "Number I/O errors that happened on this file during the sample interval. On trace files, this is the total for the whole file.",
			colsize = 9,
			aggregation = "SUM"
		},
		{
			tags = {"containers"},
			name = "Container",
			field = "container.name",
			colsize = 20
		},
		{
			name = "FILENAME",
			description = "The file name including its full path.",
			field = "fd.name",
			colsize = 0
		}
	},
	actions = 
	{
		{
			hotkey = "l",
			command = "less %fd.name",
			description = "less file",
			wait_finish = false
		},
	},
}
