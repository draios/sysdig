/*
Copyright (C) 2013-2014 Draios inc.
 
This file is part of sysdig.

sysdig is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

sysdig is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with sysdig.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "sinsp.h"
#include "sinsp_int.h"

#ifdef GATHER_INTERNAL_STATS
namespace internal_metrics
{

counter::~counter()
{
}

counter::counter()
{
	m_value = 0;
}

void registry::clear_all_metrics()
{
	for(metric_map_iterator_t it = get_metrics().begin(); it != get_metrics().end(); it++)
	{
		it->second->clear();
	}

}

}
#endif
