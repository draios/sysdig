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

view_info = 
{
	id = "LD_top_containers",
	name = "Top Containers 1",
	description = "Top Containers.",
	tags = {"Containers"},
	view_type = "table",
	applies_to = "all",
	use_defaults = true,
	columns = 
	{
		{
			name = "NA",
			field = "proc.pid",
			is_key = true
		},
		{
			name = "CPU",
			field = "proc.cpu",
			colsize = 8,
			aggregation = "AVG",
			groupby_aggregation = "SUM",
			is_sorting = true
		},
		{
			name = "PROCS",
			field = "evt.count",
			groupby_aggregation = "SUM",
			colsize = 8,
		},
		{
			name = "THREADS",
			field = "proc.nthreads",
			groupby_aggregation = "SUM",
			colsize = 5
		},
		{
			name = "VIRT",
			field = "proc.vmsize",
			groupby_aggregation = "SUM",
			colsize = 9
		},
		{
			name = "RES",
			field = "proc.vmrss",
			groupby_aggregation = "SUM",
			colsize = 9
		},
		{
			name = "FILE",
			field = "evt.buflen.file",
			colsize = 8,
			aggregation = "SUM",
			groupby_aggregation = "SUM"
		},
		{
			name = "NET",
			field = "evt.buflen.net",
			colsize = 8,
			aggregation = "SUM",
			groupby_aggregation = "SUM"
		},
		{
			name = "ID",
			field = "container.id",
			is_groupby_key = true
		},
		{
			name = "Container",
			field = "container.name",
			colsize = 15
		},
	}
}
