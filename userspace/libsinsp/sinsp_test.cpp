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