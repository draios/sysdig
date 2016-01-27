--[[
Copyright (C) Donatas Abraitis.

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
  id = "backlog",
  name = "Socket Queues",
  description = "This will show queues (backlog) utilization per process. This is useful if you have no clue what's going to with your system with heavy workload on sockets. It would help you to troubleshoot current listen() backlog, maximum backlog, which is configured by application",
  tags = {"Default"},
  view_type = "table",
  applies_to = {"", "proc.pid", "proc.name", "fd.sport", "fd.sproto"},
  filter = "evt.type=accept",
  is_root = false,
  use_defaults = true,
  drilldown_target = "connections",
  columns =
  {
    {
      name = "NA",
      field = "fd.sport",
      is_key = true
    },
    {
      name = "PID",
      field = "proc.pid",
      description = "Process ID",
      colsize = 15
    },
    {
      name = "PORT",
      field = "fd.sport",
      description = "Server port",
      colsize = 15
    },
    {
      name = "BACKLOG",
      field = "evt.arg[3]",
      description = "Current backlog size",
      colsize = 15,
      is_sorting = true,
      aggregation = "AVG"
    },
    {
      name = "BACKLOG_PCT",
      field = "evt.arg[2]",
      description = "Current backlog size in percentage",
      colsize = 15,
      aggregation = "AVG"
    },
    {
      name = "BACKLOG_MAX",
      field = "evt.arg[4]",
      description = "Max backlog size",
      colsize = 15
    },
    {
      name = "PROC",
      field = "proc.name",
      description = "Process name",
      colsize = 50
    },
  }
}
