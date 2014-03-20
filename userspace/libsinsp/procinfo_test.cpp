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
#include "../../driver/ppm_events_public.h"

#include <gtest.h>

sinsp_procinfo make_procinfo(sinsp* inspector, int64_t tid, int64_t tgid)
{
	sinsp_procinfo procinfo(inspector);
	procinfo.m_tid = tid;
	procinfo.m_tgid = tgid;
	return procinfo;	
}

sinsp_procinfo make_procinfo(int64_t tid, int64_t tgid)
{
	sinsp_procinfo procinfo;
	procinfo.m_tid = tid;
	procinfo.m_tgid = tgid;
	return procinfo;
}

sinsp_procinfo make_procinfo(int64_t tid)
{
	return make_procinfo(tid,tid);
}

TEST(procinfo_single_thread,add_non_existing_fd)
{
	sinsp_procinfo procinfo = make_procinfo(0);
	sinsp_fdinfo fdinfo;

	procinfo.add_fd(0, &fdinfo);
	EXPECT_EQ(1, procinfo.m_fdtable.count(0));
}

TEST(procinfo_single_thread,add_existing_fd)
{
	sinsp_procinfo procinfo = make_procinfo(0);
	sinsp_fdinfo fdinfo1;
	fdinfo1.m_name = "a";
	sinsp_fdinfo fdinfo2;
	fdinfo2.m_name = "b";
	procinfo.add_fd(0, &fdinfo1);
	procinfo.add_fd(0, &fdinfo2);
	EXPECT_EQ("b", procinfo.m_fdtable[0].m_name);
}

TEST(procinfo_single_thread,get_existing_fd)
{
	sinsp_procinfo procinfo = make_procinfo(0);
	sinsp_fdinfo fdinfo;
	fdinfo.m_name = "a";
	procinfo.add_fd(0, &fdinfo);
	EXPECT_EQ("a", procinfo.get_fd(0)->m_name);
}

TEST(procinfo_single_thread,get_non_existing_fd)
{
	sinsp_procinfo procinfo = make_procinfo(0);
	EXPECT_TRUE(NULL == procinfo.get_fd(0));
}

TEST(procinfo_single_thread,remove_existing_fd)
{
	sinsp_procinfo procinfo = make_procinfo(0);
	sinsp_fdinfo fdinfo;
	procinfo.add_fd(0, &fdinfo);
	procinfo.remove_fd(0);
	EXPECT_TRUE(NULL == procinfo.get_fd(0));
}

TEST(procinfo_single_thread, remove_not_existing_fd)
{
	sinsp_procinfo procinfo = make_procinfo(0);
#ifdef _DEBUG
	ASSERT_DEATH(procinfo.remove_fd(0), ".*");
#else
	procinfo.remove_fd(0);
#endif
}

TEST(procinfo_multi_thread,add_non_existing_fd)
{
	sinsp inspector;
	sinsp_procinfo parent = make_procinfo(&inspector, 0, 0);
	sinsp_procinfo child = make_procinfo(&inspector, 1, 0);
	child.m_flags = PPM_CL_CLONE_FILES;

	inspector.add_process(parent);
	inspector.add_process(child);
	
	EXPECT_TRUE(NULL == inspector.get_process(1)->get_fd(0));

	sinsp_fdinfo fdinfo;
	inspector.get_process(0)->add_fd(0, &fdinfo);

	EXPECT_TRUE(NULL != inspector.get_process(1)->get_fd(0));
}

TEST(procinfo,get_fd_table_single_thread)
{
	sinsp inspector;
	sinsp_procinfo parent = make_procinfo(&inspector, 0, 0);
	EXPECT_EQ(&(parent.m_fdtable), parent.get_fd_table());
}

TEST(procinfo,get_fd_table_multi_thread)
{
	sinsp inspector;
	// setup a process with a child thread
	sinsp_procinfo parent = make_procinfo(&inspector, 0, 0);
	sinsp_procinfo child = make_procinfo(&inspector, 1, 0);
	child.m_flags = PPM_CL_CLONE_FILES;

	inspector.add_process(parent);
	inspector.add_process(child);

	sinsp_procinfo* parent_proc = inspector.get_process(0);
	sinsp_procinfo* child_proc = inspector.get_process(1);


	// the child's fd table is the same as the parent's
	EXPECT_EQ(child_proc->get_fd_table(), parent_proc->get_fd_table());
}

TEST(procinfo,get_root_process_single_thread)
{
	sinsp inspector;
	sinsp_procinfo proc = make_procinfo(&inspector, 0, 0);
	EXPECT_EQ(&proc, proc.get_root_process());
}

TEST(procinfo,get_root_process_child_clone)
{
	sinsp inspector;
	sinsp_procinfo parent = make_procinfo(&inspector, 0, 0);
	sinsp_procinfo child = make_procinfo(&inspector, 1, 0);
	child.m_flags = PPM_CL_CLONE_FILES;
	inspector.add_process(parent);
	inspector.add_process(child);

	EXPECT_EQ(inspector.get_process(0), inspector.get_process(1)->get_root_process());
}