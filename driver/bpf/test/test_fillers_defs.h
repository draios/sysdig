#ifndef __TEST_FILLERS_DEFS_H
#define __TEST_FILLERS_DEFS_H

#include "test_fillers.h"

// increment/decrement this when adding/removing a test
#define TEST_FILLER_MAX_DEFS = 1;

TEST_FILLER(renameat2_example)
{
	struct ppm_evt_hdr *evt = data;

	const struct ppm_event_info *info = &(g_event_info[evt->type]);

	if(strcmp(info->name, "renameat2") != 0)
	{
		return;
	}

	fprintf(stdout, "PID: %d\n", evt->tid);

	if(evt->tid != getpid())
	{
		return;
	}

	uint16_t *lens = (uint16_t *)((char *)evt + sizeof(struct ppm_evt_hdr));
	char *valptr = (char *)lens + evt->nparams * sizeof(uint16_t);
	for(int j = 0; j < evt->nparams; ++j)
	{
		const struct ppm_param_info *param_info = &(info->params[j]);

		switch(param_info->type)
		{
		case PT_CHARBUF:
		{
			fprintf(stdout, " %s", valptr);
		}
		case PT_ERRNO:
		{
			int64_t val = *(int64_t *)valptr;
			if(val < 0)
			{
				fprintf(stdout,
					" errno: %" PRId64, val);
			}
		}
		default:
		{
		};
		}

		fprintf(stdout, "\n");
		valptr += lens[j];
	}
}

#endif //__TEST_FILLERS_DEFS_H