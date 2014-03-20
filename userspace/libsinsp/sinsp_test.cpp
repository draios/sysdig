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

#include <gtest.h>
#include "sinsp.h"
#include "../../driver/ppm_events_public.h"

TEST(inspector,get_proc_by_invalid_tid)
{
	sinsp inspector;
	EXPECT_TRUE(NULL == inspector.get_process(-100));
}

TEST(inspector,get_proc_by_valid_tid)
{
	sinsp inspector;
	EXPECT_TRUE(NULL == inspector.get_process(-100));
	sinsp_procinfo newpi(&inspector);
	newpi.m_tgid = -100;
	inspector.m_proctable[-100] = newpi;

	EXPECT_TRUE(NULL != inspector.get_process(-100));
}