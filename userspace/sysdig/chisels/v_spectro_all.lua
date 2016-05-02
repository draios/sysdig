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
	id = "spectro_all",
	name = "Spectrogram-All",
	description = "System call latency spectrogram.",
	view_type = "spectrogram",
	applies_to = {"evt.type"},
	filter = "evt.dir=<",
	use_defaults = false,
	columns = 
	{
		{
			name = "NA",
			field = "evt.latency.quantized",
			is_key = true
		},
		{
			name = "LATENCY",
			description = "system call latency.",
			field = "evt.latency.quantized",
		},
		{
			name = "COUNT",
			description = "XXX.",
			field = "evt.count",
			aggregation = "SUM",
			colsize = 8,
		}
	}
}
