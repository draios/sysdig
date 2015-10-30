/*
Copyright (C) 2013-2014 Draios inc.

This file is part of sysdig.

sysdig is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.

sysdig is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with sysdig.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <signal.h>
#include <scap.h>

uint64_t g_nevts = 0;

static void signal_callback(int signal)
{
	printf("events captured: %" PRIu64 "\n", g_nevts);
	exit(0);
}

int main(int argc, char** argv)
{
	char error[SCAP_LASTERR_SIZE];
	int32_t res;
	scap_evt* ev;
	uint16_t cpuid;

	if(signal(SIGINT, signal_callback) == SIG_ERR)
	{
		fprintf(stderr, "An error occurred while setting SIGINT signal handler.\n");
		return -1;
	}

	scap_t* h = scap_open_live(error);
	if(h == NULL)
	{
		fprintf(stderr, "%s\n", error);
		return -1;
	}
	
	while(1)
	{
		res = scap_next(h, &ev, &cpuid);

		if(res > 0)
		{
			fprintf(stderr, "%s\n", scap_getlasterr(h));
			scap_close(h);
			return -1;
		}

		if(res != SCAP_TIMEOUT)
		{
			g_nevts++;
		}
	}

	scap_close(h);
	return 0;
}
