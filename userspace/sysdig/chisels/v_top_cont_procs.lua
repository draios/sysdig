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
	id = "top_cont_procs",
	name = "Top Processes",
	description = "Top Processes.",
	tags = {"Containers"},
	view_type = "table",
	applies_to = "all,container.id",
	use_defaults = true,
	columns = 
	{
		{
			name = "NA",
			field = "proc.pid",
			is_key = true
		},
		{
			name = "PID",
			field = "proc.pid",
			colsize = 8,
		},
		{
			name = "VPID",
			field = "proc.vpid",
			colsize = 8,
		},
		{
			name = "CPU",
			field = "proc.cpu",
			colsize = 8,
			aggregation = "AVG",
			is_sorting = true
		},
		{
			name = "TH",
			field = "proc.nthreads",
			colsize = 5
		},
		{
			name = "VIRT",
			field = "proc.vmsize",
			colsize = 9
		},
		{
			name = "RES",
			field = "proc.vmrss",
			colsize = 9
		},
		{
			name = "FILE",
			field = "evt.buflen.file",
			colsize = 8,
			aggregation = "SUM"
		},
		{
			name = "NET",
			field = "evt.buflen.net",
			colsize = 8,
			aggregation = "SUM"
		},
		{
			name = "Container",
			field = "container.name",
			colsize = 15
		},
		{
			name = "Command",
			field = "proc.exeline",
			colsize = 200
		}
	}
}
