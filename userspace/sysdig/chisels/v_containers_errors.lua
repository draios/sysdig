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
	id = "containers_errors",
	name = "Containers Errors",
	description = "This view shows system error counters for each container running on the machine. Errors are grouped into 4 categories: file I/O, network I/O, memory allocation and 'other'.",
	tips = {
		"If you click 'enter' on a selection in this chart, you will be able to see the specific errors that the container is generating.",
		"Digging into a container by clicking on F6 will let you explore the system calls for that specific container and see the full details about what's causing the errors."
	},
	tags = {"Default"},
	view_type = "table",
	applies_to = {"", "container.id", "fd.name", "fd.sport", "evt.type", "fd.directory"},
	drilldown_target = "errors",
	filter = "container.name != host",
	use_defaults = true,
	columns = 
	{
		{
			name = "NA",
			field = "proc.pid",
			is_key = true
		},
		{
			name = "ID",
			field = "container.id",
			is_groupby_key = true
		},
		{
			name = "FILE",
			field = "evt.count.error.file",
			description = "Number of file I/O errors generated in the container during the sample interval. On trace files, this is the total for the whole file.",
			colsize = 8,
			aggregation = "SUM",
			groupby_aggregation = "SUM"
		},
		{
			name = "NET",
			field = "evt.count.error.net",
			description = "Number of network I/O errors generated in the container during the sample interval. On trace files, this is the total for the whole file.",
			colsize = 8,
			aggregation = "SUM",
			groupby_aggregation = "SUM"
		},
		{
			name = "MEMORY",
			field = "evt.count.error.memory",
			description = "Number of memory allocation/release related errors generated in the container during the sample interval. On trace files, this is the total for the whole file.",
			colsize = 8,
			aggregation = "SUM",
			groupby_aggregation = "SUM"
		},
		{
			name = "OTHER",
			field = "evt.count.error.other",
			description = "Number of errors generated in the container that don't fall in any of the previous categories. E.g. signal or event related errors. On trace files, this is the total for the whole file.",
			colsize = 8,
			aggregation = "SUM",
			groupby_aggregation = "SUM"
		},
		{
			name = "Container",
			field = "container.name",
			description = "Name of the container. What this field contains depends on the containerization technology. For example, for docker this is the content of the 'NAMES' column in 'docker ps'",
			colsize = 15
		}
	}
}
