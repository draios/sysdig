#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <fcntl.h>

#include <sinsp.h>
#include "source_plugin.h"

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#include <getopt.h>
#endif

typedef struct test_plugin_state
{
	char databuf[4096];
}test_plugin_state;

src_plugin_t* testinit(char* config, char *error, int32_t* rc)
{
	*rc = SCAP_SUCCESS;

	test_plugin_state* s = (test_plugin_state*)malloc(sizeof(test_plugin_state));
	if(s == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "plugin state allocation failure");
		*rc = SCAP_FAILURE;
	}

	return s;
}

void testdestroy(src_plugin_t* s)
{
	if(s)
	{
		free(s);
	}
}

uint32_t testget_id()
{
	return 1;
}

char* testget_name()
{
	return (char*)"kmsg";
}

char* testget_fields()
{
	return (char*)"[{\"type\": \"string\", \"name\": \"kmsg.source\", \"desc\":\"process\"}]";
}

#define DMESG_FILE_NAME "dmesg.txt"
src_instance_t* testopen(src_plugin_t* s, char *error, int32_t* rc)
{
	*rc = SCAP_SUCCESS;

	int fd = _open(DMESG_FILE_NAME, _O_BINARY | _O_RDONLY);
	if(fd < 0)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "dmesg plugin open error: cannot open %s", DMESG_FILE_NAME);
		*rc = SCAP_FAILURE;
	}

	return (src_instance_t*)(uint64_t)fd;
}

void testclose(src_plugin_t* s, src_instance_t* h)
{
	if(h != NULL)
	{
		_close((int)(int64_t)h);
	}
}

int32_t testnext(src_plugin_t* s, src_instance_t* h, uint8_t** data, uint32_t* datalen)
{
//	(*pevent)->type = PPME_SYSCALL_OPEN_E;
	test_plugin_state* ts = (test_plugin_state*)s;
	snprintf(ts->databuf, 4096, "ci\5o");
	*data = (uint8_t*)ts->databuf;
	*datalen = 4;
	return SCAP_SUCCESS;
}

char* testevent_to_string(uint8_t* data, uint32_t datalen)
{
	return (char*)"dete";
}

char* testextract_as_string(uint32_t id, uint8_t* data, uint32_t datalen)
{
	return (char*)"estratto stringatto";
}

source_plugin_info create_test_source()
{
	source_plugin_info si =
	{
		.open = testopen,
		.close = testclose,
		.next = testnext,
		.init = testinit,
		.destroy = testdestroy,
		.get_id = testget_id,
		.get_name = testget_name,
		.get_fields = testget_fields,
		.event_to_string = testevent_to_string,
		.extract_as_string = testextract_as_string
	};

	return si;
}
