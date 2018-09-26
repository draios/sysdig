/*
Copyright (C) 2013-2018 Draios Inc dba Sysdig.

This file is part of sysdig.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

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

	scap_t* h = scap_open_live(error, &res);
	if(h == NULL)
	{
		fprintf(stderr, "%s (%d)\n", error, res);
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
