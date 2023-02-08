/*
Copyright (C) 2013-2020 Sysdig Inc.

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

#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <iostream>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <assert.h>
#include <algorithm>
#include <unordered_set>

#include <sinsp.h>
#include "scap_open_exception.h"
#include "chisel_capture_interrupt_exception.h"
#ifdef HAS_CAPTURE
#ifndef WIN32
#include "driver_config.h"
#endif // WIN32
#endif // HAS_CAPTURE
#include "sysdig.h"
#ifdef HAS_CHISELS
#include "chisel.h"
#include "chisel_utils.h"
#include "chisel_fields_info.h"
#endif
#include "fields_info.h"
#include "utils.h"
#include "plugin.h"
#include "plugin_manager.h"

#include "utils/sinsp_opener.h"
#include "utils/plugin_utils.h"
#include "utils/supported_events.h"
#include "utils/supported_fields.h"

#ifdef _WIN32
#include "win32/getopt.h"
#include <io.h>
#else
#include <unistd.h>
#include <getopt.h>
#include <termios.h>
#endif

static constexpr const char* g_unknown_field_err = "nonexistent field ";

static bool g_terminate = false;
static bool g_terminating = false;
static bool g_plugin_input = false;
#ifdef HAS_CHISELS
std::vector<sinsp_chisel*> g_chisels;
#endif

static void usage();

//
// Helper functions
//
static void signal_callback(int signal)
{
	if(g_plugin_input)
	{
		//
		// Input plugins can get stuck in next().
		// When we are using one, check again in few seconds and force a quit
		// if we are stuck.
		//
		if(g_terminate == true && g_terminating == false)
		{
			exit(0);
		}
		else
		{
			g_terminate = true;
#ifndef _WIN32
			alarm(3);
#endif
		}
	}
	else
	{
		g_terminate = true;
	}
}

//
// Program help
//
static void usage()
{
    printf(
"sysdig version " SYSDIG_VERSION "\n"
"Usage: sysdig [options] [-p <output_format>] [filter]\n\n"
"Options:\n"
" -A, --print-ascii  Only print the text portion of data buffers, and echo\n"
"                    end-of-lines. This is useful to only display human-readable\n"
"                    data.\n"
" -b, --print-base64 Print data buffers in base64. This is useful for encoding\n"
"                    binary data that needs to be used over media designed to\n"
"                    handle textual data (i.e., terminal or json).\n"
" -B<bpf_probe>, --bpf=<bpf_probe>\n"
"                    Enable live capture using the specified BPF probe instead of the kernel module.\n"
"                    The BPF probe can also be specified via the environment variable\n"
"                    SYSDIG_BPF_PROBE. If <bpf_probe> is left empty, sysdig will\n"
"                    try to load one from the scap-driver-loader script.\n"
#ifdef HAS_CHISELS
" -c <chiselname> <chiselargs>, --chisel <chiselname> <chiselargs>\n"
"                    run the specified chisel. If the chisel require arguments,\n"
"                    they must be specified in the command line after the name.\n"
" -cl, --list-chisels\n"
"                    lists the available chisels. Sysdig looks for chisels in the\n"
"                    following directories: ./chisels, ~/.chisels, " SYSDIG_CHISELS_DIR ".\n"
#endif
#ifdef HAS_MODERN_BPF
"  --cpus-for-each-buffer <cpus_num>\n"
"                    [EXPERIMENTAL] Please note this config regards only the modern BPF probe.\n"
"                    They are experimental so they could change over releases.\n"
"                    How many CPUs you want to assign to a single syscall buffer (ring buffer).\n"
"                    By default, every syscall buffer is associated to 2 CPUs, so the mapping is\n"
"                    1:2. The modern BPF probe allows you to choose different mappings, for\n"
"                    example, 1:1 would mean a syscall buffer for each CPU.\n"
#endif
" -C <file_size>, --file-size=<file_size>\n"
"                    Before writing an event, check whether the file is\n"
"                    currently larger than file_size and, if so, close the\n"
"                    current file and open a new one. Saved files will have the\n"
"                    name specified with the -w flag, with a number after it,\n"
"                    starting at 0 and continuing upward. The units of file_size\n"
"                    are millions of bytes (10^6, not 2^20). Use the -W flag to\n"
"                    determine how many files will be saved to disk.\n"
#ifdef HAS_CAPTURE
#ifndef MINIMAL_BUILD
" --cri <path>       Path to CRI socket for container metadata\n"
"                    Use the specified socket to fetch data from a CRI-compatible runtime\n"
"\n"
" --cri-timeout <timeout_ms>\n"
"                    Wait at most <timeout_ms> milliseconds for response from CRI\n"
#endif // MINIMAL_BUILD
#endif // HAS_CAPTURE
" -d, --displayflt   Make the given filter a display one\n"
"                    Setting this option causes the events to be filtered\n"
"                    after being parsed by the state system. Events are\n"
"                    normally filtered before being analyzed, which is more\n"
"                    efficient, but can cause state (e.g. FD names) to be lost.\n"
" -D, --debug        Capture events about sysdig itself, display internal events\n"
"                    in addition to system events, and print additional\n"
"                    logging on standard error.\n"
" -E, --exclude-users\n"
"                    Don't create the user/group tables by querying the OS when\n"
"                    sysdig starts. This also means that no user or group info\n"
"                    will be written to the trace file by the -w flag.\n"
"                    The user/group tables are necessary to use filter fields\n"
"                    like user.name or group.name. However, creating them can\n"
"                    increase sysdig's startup time. Moreover, they contain\n"
"                    information that could be privacy sensitive.\n"
" -e <num_events>    If used together with -w option, creates a series of dump files\n"
"                    containing only a specified number of events given in num_events\n"
"                    parameter each.\n"
"                    Used alongside -W flags creates a ring buffer of file containing\n"
"                    num_events each.\n"
" -F, --fatfile      Enable fatfile mode\n"
"                    when writing in fatfile mode, the output file will contain\n"
"                    events that will be invisible when reading the file, but\n"
"                    that are necessary to fully reconstruct the state.\n"
"                    Fatfile mode is useful when saving events to disk with an\n"
"                    aggressive filter. The filter could drop events that would\n"
"                    the state to be updated (e.g. clone() or open()). With\n"
"                    fatfile mode, those events are still saved to file, but\n"
"                    'hidden' so that they won't appear when reading the file.\n"
"                    Be aware that using this flag might generate substantially\n"
"                    bigger traces files.\n"
" --filter-proclist  apply the filter to the process table\n"
"                    a full dump of /proc is typically included in any trace file\n"
"                    to make sure all the state required to decode events is in the\n"
"                    file. This could cause the file to contain unwanted or sensitive\n"
"                    information. Using this flag causes the command line filter to\n"
"                    be applied to the /proc dump as well.\n"
" -g, --gvisor-config\n"
"                    Parse events from gVisor using the specified configuration file.\n"
"                    A sysdig-compatible configuration file can be generated with --gvisor-generate-config\n"
"                    and can be used for both runsc and sysdig.\n"
" --gvisor-generate-config [=<socket_path>(=/tmp/gvisor.sock)]\n"
"                    Generate a configuration file that can be used for gVisor.\n"
" --gvisor-root <gvisor_root>\n"
"                    gVisor root directory for storage of container state. Equivalent to runsc --root flag.\n"
" -G <num_seconds>, --seconds=<num_seconds>\n"
"                    Rotates the dump file specified with the -w option every\n"
"                    num_seconds seconds. Saved files will have the name specified\n"
"                    by -w which should include a time format as defined by strftime(3).\n"
"                    If no time format is specified, a counter will be used.\n"
"                    If no data format is specified, this can be used with -W flag to\n"
"                    create a ring buffer of events.\n"
" -h, --help         Print this page\n"
" -H <pluginname>[:<initconfig>], --plugin <pluginname>[:<initconfig>]\n"
"                    Registers a plugin, using the passed init config if present.\n"
"                    The format of initconf is controlled by the plugin, refer to each\n"
"                    plugin's documentation to learn about it.\n"
"                    A path can also be used as pluginname.\n"
" -I <pluginname>[:<openparams>], --input <pluginname>[:<openparams>]\n"
"                    Set a previously registered plugin as input,\n"
"                    capturing events using it and passing the \n"
"                    openparams string as open parameters.\n"
"                    Only a single source plugin can be registered.\n"
"                    If no plugins were registered, any found plugin in the directories\n"
"                    specified by ;-separated environment variable SYSDIG_PLUGIN_DIR and\n"
"                    in " SYSDIG_PLUGINS_DIR " is registered; then use the provided one as input source.\n"
"                    The format of openparams is controlled by the plugin, refer to each\n"
"                    plugin's documentation to learn about it.\n"
"                    See https://falco.org/docs/plugins/plugin-api-reference/#ss-plugin-t-plugin-init-const-char-config-int32-t-rc-required-yes\n"
"                    and https://falco.org/docs/plugins/plugin-api-reference/#ss-instance-t-plugin-open-ss-plugin-t-s-const-char-params-int32-t-rc-required-yes for more infos.\n"
"                    The event sources available for capture vary depending on which \n"
"                    plugins have been installed.\n"
" -Il                Lists the loaded plugins. If no plugin has been registered through '-H',\n"
"                    Sysdig looks for plugins in the directories \n"
"                    specified by ;-separated environment variable SYSDIG_PLUGIN_DIR and\n"
"                    in " SYSDIG_PLUGINS_DIR ".\n"
#ifdef HAS_CHISELS
" -i <chiselname>, --chisel-info <chiselname>\n"
"                    Get a longer description and the arguments associated with\n"
"                    a chisel found in the -cl option list.\n"
#endif
" -j, --json         Emit output as json, data buffer encoding will depend from the\n"
"                    print format selected.\n"
#ifndef MINIMAL_BUILD
" -k <url>, --k8s-api=<url>\n"
"                    Enable Kubernetes support by connecting to the API server\n"
"                    specified as argument. E.g. \"http://admin:password@127.0.0.1:8080\".\n"
"                    The API server can also be specified via the environment variable\n"
"                    SYSDIG_K8S_API.\n"
" --node-name=<url>\n"
"                    The node name is used as a filter when requesting metadata of pods\n"
"                    to the API server; if empty, no filter is set\n"
" -K <bt_file> | <cert_file>:<key_file[#password]>[:<ca_cert_file>], --k8s-api-cert=<bt_file> | <cert_file>:<key_file[#password]>[:<ca_cert_file>]\n"
"                    Use the provided files names to authenticate user and (optionally) verify the K8S API\n"
"                    server identity.\n"
"                    Each entry must specify full (absolute, or relative to the current directory) path\n"
"                    to the respective file.\n"
"                    Private key password is optional (needed only if key is password protected).\n"
"                    CA certificate is optional. For all files, only PEM file format is supported. \n"
"                    Specifying CA certificate only is obsoleted - when single entry is provided \n"
"                    for this option, it will be interpreted as the name of a file containing bearer token.\n"
"                    Note that the format of this command-line option prohibits use of files whose names contain\n"
"                    ':' or '#' characters in the file name.\n"
"                    Option can also be provided via the environment variable SYSDIG_K8S_API_CERT.\n"
#endif // MINIMAL_BUILD
" -L, --list-events  List the events that the engine supports\n"
" -l, --list         List the fields that can be used for filtering and output\n"
"                    formatting. Use -lv to get additional information for each\n"
"                    field.\n"
" --libs-version     Print the falcosecurity/libs version\n"
" --large-environment\n"
"                    Support environments larger than 4KiB\n"
"                    When the environment is larger than 4KiB, load the whole\n"
"                    environment from /proc instead of truncating to the first 4KiB\n"
"                    This may fail for short-lived processes and in that case\n"
"                    the truncated environment is used instead.\n"
" --log-level=<trace|debug|info|notice|warning|error|critical|fatal>\n"
"                    Select log level. Useful together with --debug.\n"
" --list-markdown    like -l, but produces markdown output\n"
" -m <url[,marathon_url]>, --mesos-api=<url[,marathon_url]>\n"
"                    Enable Mesos support by connecting to the API server\n"
"                    specified as argument. E.g. \"http://admin:password@127.0.0.1:5050\".\n"
"                    Marathon url is optional and defaults to Mesos address, port 8080.\n"
"                    The API servers can also be specified via the environment variable\n"
"                    SYSDIG_MESOS_API.\n"
#ifdef HAS_MODERN_BPF
"--modern-bpf\n"
"                    [EXPERIMENTAL] Enable live capture using the modern BPF probe instead of\n"
"                    of the kernel module.\n"
#endif
" -M <num_seconds>   Stop collecting after <num_seconds> reached.\n"
" -n <num>, --numevents=<num>\n"
"                    Stop capturing after <num> events\n"
" --page-faults      Capture user/kernel major/minor page faults\n"
" --plugin-config-file\n"
"                    Load the plugin configuration from a Falco-compatible yaml file.\n"
"                    Do not mix this option with the '-H' or '-I' options: it is unsupported.\n"
"                    See the plugin section in https://falco.org/docs/configuration/ for\n"
"                    additional information\n"
" -P, --progress     Print progress on stderr while processing trace files\n"
" -p <output_format>, --print=<output_format>\n"
"                    Specify the format to be used when printing the events.\n"
"                    With -pc or -pcontainer will use a container-friendly format.\n"
"                    With -pk or -pkubernetes will use a kubernetes-friendly format.\n"
"                    With -pm or -pmesos will use a mesos-friendly format.\n"
"                    See the examples section below for more info.\n"
" --plugin-info <pluginname>\n"
"                    Print info for a single plugin. This includes name, author,\n"
"                    and all the descriptive info of the plugin. If present,\n"
"                    this also prints the schema format for the init configuration\n"
"                    and a list of suggested open parameters.\n"
"                    All this info is controlled by the plugin, refer to each\n"
"                    plugin's documentation to learn more about it.\n"
"                    This can be combined with the -H option to load the plugin\n"
"                    with a given configuration.\n"
"                    A path can also be used as pluginname.\n"
" -q, --quiet        Don't print events on the screen\n"
"                    Useful when dumping to disk.\n"
" -R                 Resolve port numbers to names.\n"
" -r <readfile>, --read=<readfile>\n"
"                    Read the events from <readfile>.\n"
" -S, --summary      print the event summary (i.e. the list of the top events)\n"
"                    when the capture ends.\n"
" -s <len>, --snaplen=<len>\n"
"                    Capture the first <len> bytes of each I/O buffer.\n"
"                    By default, the first 80 bytes are captured. Use this\n"
"                    option with caution, it can generate huge trace files.\n"
" -t <timetype>, --timetype=<timetype>\n"
"                    Change the way event time is displayed. Accepted values are\n"
"                    h for human-readable string, a for absolute timestamp from\n"
"                    epoch, r for relative time from the beginning of the\n"
"                    capture, d for delta between event enter and exit, and\n"
"                    D for delta from the previous event.\n"
" -T, --force-tracers-capture\n"
"                    Tell the driver to make sure full buffers are captured from\n"
"                    /dev/null, to make sure that tracers are completely\n"
"                    captured. Note that sysdig will enable extended /dev/null\n"
"                    capture by itself after detecting that tracers are written\n"
"                    there, but that could result in the truncation of some\n"
"                    tracers at the beginning of the capture. This option allows\n"
"                    preventing that.\n"
" --unbuffered       Turn off output buffering. This causes every single line\n"
"                    emitted by sysdig to be flushed, which generates higher CPU\n"
"                    usage but is useful when piping sysdig's output into another\n"
"                    process or into a script.\n"
" -U, --suppress-comm\n"
"                    Ignore all events from processes having the provided comm.\n"
" -v, --verbose      Verbose output.\n"
"                    This flag will cause the full content of text and binary\n"
"                    buffers to be printed on screen, instead of being truncated\n"
"                    to 40 characters. Note that data buffers length is still\n"
"                    limited by the snaplen (refer to the -s flag documentation)\n"
"                    -v will also make sysdig print some summary information at\n"
"                    the end of the capture.\n"
" --version          Print version number.\n"
" -w <writefile>, --write=<writefile>\n"
"                    Write the captured events to <writefile>.\n"
" -W <num>, --limit <num>\n"
"                    Used in conjunction with the -C option, this will limit the number\n"
"                    of files created to the specified number, and begin overwriting files\n"
"                    from the beginning, thus creating a 'rotating' buffer.\n"
"\n"
"                    Used in conjunction with the -G option, this will limit the number\n"
"                    of rotated dump files that get created, exiting with status 0 when\n"
"                    reaching the limit. If used with -C as well, the behavior will result\n"
"                    in cyclical files per timeslice.\n"
" -x, --print-hex    Print data buffers in hex.\n"
" -X, --print-hex-ascii\n"
"                    Print data buffers in hex and ASCII.\n"
" -z, --compress     Used with -w, enables compression for trace files.\n"
"\n"
"Output format:\n\n"
"By default, sysdig prints the information for each captured event on a single\n"
" line with the following format:\n\n"
" %%evt.num %%evt.outputtime %%evt.cpu %%proc.name (%%thread.tid) %%evt.dir %%evt.type %%evt.info\n\n"
"where:\n"
" evt.num is the incremental event number\n"
" evt.time is the event timestamp\n"
" evt.cpu is the CPU number where the event was captured\n"
" proc.name is the name of the process that generated the event\n"
" thread.tid id the TID that generated the event, which corresponds to the\n"
"   PID for single thread processes\n"
" evt.dir is the event direction, > for enter events and < for exit events\n"
" evt.type is the name of the event, e.g. 'open' or 'read'\n"
" evt.info is the list of event arguments.\n\n"
"The output format can be customized with the -p switch, using any of the\n"
"fields listed by 'sysdig -l'.\n\n"
"Using -pc or -pcontainer, the default format will be changed to a container-friendly one:\n\n"
"%%evt.num %%evt.outputtime %%evt.cpu %%container.name (%%container.id) %%proc.name (%%thread.tid:%%thread.vtid) %%evt.dir %%evt.type %%evt.info\n\n"
"Using -pk or -pkubernetes, the default format will be changed to a kubernetes-friendly one:\n\n"
"%%evt.num %%evt.outputtime %%evt.cpu %%k8s.pod.name (%%container.id) %%proc.name (%%thread.tid:%%thread.vtid) %%evt.dir %%evt.type %%evt.info\n\n"
"Using -pm or -pmesos, the default format will be changed to a mesos-friendly one:\n\n"
"%%evt.num %%evt.outputtime %%evt.cpu %%mesos.task.name (%%container.id) %%proc.name (%%thread.tid:%%thread.vtid) %%evt.dir %%evt.type %%evt.info\n\n"
"Examples:\n\n"
" Capture all the events from the live system and print them to screen\n"
"   $ sysdig\n\n"
" Capture all the events from the live system and save them to disk\n"
"   $ sysdig -w dumpfile.scap\n\n"
" Read events from a file and print them to screen\n"
"   $ sysdig -r dumpfile.scap\n\n"
" Print all the open system calls invoked by cat\n"
"   $ sysdig proc.name=cat and evt.type=open\n\n"
" Print the name of the files opened by cat\n"
"   $ sysdig -p\"%%evt.arg.name\" proc.name=cat and evt.type=open\n\n"
" Register any found plugin and use dummy as input source passing to it open params\n"
"   $ sysdig -I dummy:10'\n\n"
" Load and register dummy source plugin passing to it init config and open params\n"
"   $ sysdig -H dummy:'{\"jitter\":50}' -I dummy:10\n\n"
    );
}

double g_last_printed_progress_pct = 0;
char g_prg_line_buf[512] = "";

inline void clean_last_progress_line()
{
	uint32_t j;

	for(j = 0; j < strlen(g_prg_line_buf); j++)
	{
		g_prg_line_buf[j] = ' ';
	}
	g_prg_line_buf[j] = 0;

	fprintf(stderr, "\r%s", g_prg_line_buf);
}

inline void output_progress(sinsp* inspector, sinsp_evt* ev)
{
	if(ev == NULL || (ev->get_num() % 10000 == 0))
	{
		std::string ps;
		double progress_pct = inspector->get_read_progress_with_str(&ps);

		if(progress_pct - g_last_printed_progress_pct > 0.1)
		{
			clean_last_progress_line();
			if(ps == "")
			{
				snprintf(g_prg_line_buf, sizeof(g_prg_line_buf), "%.2lf", progress_pct);
			}
			else
			{
				snprintf(g_prg_line_buf, sizeof(g_prg_line_buf), "%s", ps.c_str());
			}

			fprintf(stderr, "\r%s", g_prg_line_buf);
			fflush(stderr);
			g_last_printed_progress_pct = progress_pct;
		}
	}
}

void print_summary_table(sinsp* inspector,
						 std::vector<summary_table_entry> &summary_table,
						 uint32_t nentries)
{
	sinsp_evttables* einfo = inspector->get_event_info_tables();

	std::cout << "----------------------\n";
	std::string tstr = std::string("Event");
	tstr.resize(16, ' ');
	tstr += "#Calls\n";
	std::cout << tstr;
	std::cout << "----------------------\n";

	sort(summary_table.begin(), summary_table.end(),
		summary_table_entry_rsort_comparer());

	for(uint32_t j = 0; j < nentries; j++)
	{
		const summary_table_entry &e = summary_table.at(j);

		if(e.m_ncalls == 0)
		{
			break;
		}

		if(e.m_is_unsupported_syscall)
		{
			tstr = einfo->m_syscall_info_table[e.m_id / 2].name;
			tstr.resize(16, ' ');

			printf("%s%s%" PRIu64 "\n",
				(PPME_IS_ENTER(e.m_id))? "> ": "< ",
				tstr.c_str(),
				e.m_ncalls);
		}
		else
		{
			tstr = einfo->m_event_info[e.m_id].name;
			tstr.resize(16, ' ');

			printf("%s%s%" PRIu64 "\n",
				(PPME_IS_ENTER(e.m_id))? "> ": "< ",
				tstr.c_str(),
				e.m_ncalls);
		}
	}
}

#ifdef HAS_CHISELS
static void add_chisel_dirs(sinsp* inspector)
{
	//
	// Add the default chisel directory statically configured by the build system
	//
	chisel_add_dir(SYSDIG_CHISELS_DIR, false);

	//
	// Add the directories configured in the SYSDIG_CHISEL_DIR environment variable
	//
	char* s_user_cdirs = getenv("SYSDIG_CHISEL_DIR");

	if(s_user_cdirs != NULL)
	{
		std::vector<std::string> user_cdirs = sinsp_split(s_user_cdirs, ';');

		for(uint32_t j = 0; j < user_cdirs.size(); j++)
		{
			chisel_add_dir(user_cdirs[j], true);
		}
	}
}
#endif

static void initialize_chisels()
{
#ifdef HAS_CHISELS
	for(uint32_t j = 0; j < g_chisels.size(); j++)
	{
		g_chisels[j]->on_init();
	}
#endif
}

//
// Parse the command line following a chisel to consume the chisel command line.
// We use the following strategy:
//  - if the chisel has no arguments, we don't consume anything
//  - if the chisel has at least one required argument, we consume the next command line token
//  - if the chisel has only optional arguments, we consume the next token, unless
//    - there is no next token
//    - the next token starts with a '-'
//    - the rest of the command line contains a valid filter
//
static void parse_chisel_args(sinsp_chisel* ch, sinsp* inspector, int optind, int argc, char **argv, int32_t* n_filterargs)
{
	uint32_t nargs = ch->get_n_args();
	uint32_t nreqargs = ch->get_n_required_args();
	std::string args;

	if(nargs != 0)
	{
		if(optind > (int32_t)argc)
		{
			throw sinsp_exception("invalid number of arguments for chisel " + std::string(optarg) + ", " + std::to_string((long long int)nargs) + " expected.");
		}
		else if(optind < (int32_t)argc)
		{
			args = argv[optind];

			if(nreqargs != 0)
			{
				ch->set_args(args);
				(*n_filterargs)++;
			}
			else
			{
				if(args[0] != '-')
				{
					std::string testflt;

					for(int32_t j = optind; j < argc; j++)
					{
						testflt += argv[j];
						if(j < argc - 1)
						{
							testflt += " ";
						}
					}

					if(nargs == 1 && ch->get_lua_script_info()->m_args[0].m_type == "filter")
					{
						ch->set_args(args);
						(*n_filterargs)++;
					}
					else
					{
						try
						{
							sinsp_filter_compiler compiler(inspector, testflt);
							sinsp_filter* s = compiler.compile();
							delete s;
						}
						catch(...)
						{
							ch->set_args(args);
							(*n_filterargs)++;
						}
					}
				}
			}
		}
		else
		{
			if(nreqargs != 0)
			{
				throw sinsp_exception("missing arguments for chisel " + std::string(optarg));
			}
		}
	}
}

static void free_chisels()
{
#ifdef HAS_CHISELS
	for(auto & g_chisel : g_chisels)
	{
		delete g_chisel;
	}

	g_chisels.clear();
#endif
}

static void chisels_on_capture_start()
{
#ifdef HAS_CHISELS
	for(auto & g_chisel : g_chisels)
	{
		g_chisel->on_capture_start();
	}
#endif
}

static void chisels_on_capture_end()
{
#ifdef HAS_CHISELS
	for(auto & g_chisel : g_chisels)
	{
		g_chisel->on_capture_end();
	}
#endif
}

static void chisels_do_timeout(sinsp_evt* ev)
{
#ifdef HAS_CHISELS
	for(std::vector<sinsp_chisel*>::iterator it = g_chisels.begin();
		it != g_chisels.end(); ++it)
	{
		(*it)->do_timeout(ev);
	}
#endif
}

void handle_end_of_file(sinsp* inspector, bool print_progress, bool reset_colors = false, sinsp_evt_formatter* formatter = NULL)
{
	std::string line;

	// Notify the formatter that we are at the
	// end of the capture in case it needs to
	// write any terminating characters
	if(formatter != NULL && formatter->on_capture_end(&line))
	{
		std::cout << line << std::endl;
	}

	if(reset_colors) {
		std::cout << "\e[00m";
	}

	//
	// Reached the end of a trace file.
	// If we are reporting progress, this is 100%
	//
	if(print_progress)
	{
		clean_last_progress_line();
		if(inspector == NULL)
		{
			fprintf(stderr, "\r100.00\n");
		}
		else
		{
			output_progress(inspector, NULL);
			fprintf(stderr, "\n");
		}

		fflush(stderr);
	}

	//
	// Notify the chisels that we're exiting.
	//
	try
	{
		chisels_on_capture_end();
	}
	catch(...)
	{
	}
}

std::vector<std::string> split_nextrun_args(std::string na)
{
	std::vector<std::string> res;
	uint32_t laststart = 0;
	uint32_t j;
	bool inquote = false;

	for(j = 0; j < na.size(); j++)
	{
		if(na[j] == '"')
		{
			inquote = !inquote;
		}
		else if(na[j] == ' ')
		{
			if(!inquote)
			{
				std::string arg = na.substr(laststart, j - laststart);
				replace_in_place(arg, "\"", "");
				res.push_back(arg);
				laststart = j + 1;
			}
		}
	}

	res.push_back(na.substr(laststart, j - laststart));
	laststart = j + 1;

	return res;
}

//
// Event processing loop
//
captureinfo do_inspect(sinsp* inspector,
	uint64_t cnt,
	uint64_t duration_to_tot_ns,
	bool quiet,
	bool json,
	bool do_flush,
	bool reset_colors,
	bool print_progress,
	sinsp_filter* display_filter,
	std::vector<summary_table_entry> &summary_table,
	sinsp_evt_formatter* syscall_evt_formatter,
	sinsp_evt_formatter* plugin_evt_formatter)
{
	captureinfo retval;
	int32_t res;
	sinsp_evt* ev;
	std::string line;
	uint64_t duration_start = 0;

	if(json)
	{
		do_flush = true;
	}

	// This changes between syscall_evt_formatter and
	// plugin_evt_formatter based on the event type.
	sinsp_evt_formatter *formatter = syscall_evt_formatter;

	inspector->start_capture();

	//
	// Loop through the events
	//
	while(1)
	{
		if(retval.m_nevts == cnt || g_terminate)
		{
			//
			// End of capture, either because the user stopped it, or because
			// we reached the event count specified with -n.
			//
			if(g_terminate)
			{
				g_terminating = true;
			}
			handle_end_of_file(inspector, print_progress, reset_colors, formatter);
			break;
		}
		res = inspector->next(&ev);

		if(res == SCAP_TIMEOUT || res == SCAP_FILTERED_EVENT)
		{
			if(res == SCAP_FILTERED_EVENT && ev != NULL && ev->is_filtered_out())
			{
				//
				// The event has been dropped by the filtering system.
				// Give the chisels a chance to run their timeout logic.
				//
				chisels_do_timeout(ev);

				if(print_progress)
				{
					output_progress(inspector, ev);
				}
			}

			continue;
		}
		else if(res == SCAP_EOF)
		{
			handle_end_of_file(inspector, print_progress, reset_colors, formatter);
			break;
		}
		else if(res != SCAP_SUCCESS)
		{
			//
			// Event read error.
			// Notify the chisels that we're exiting, and then die with an error.
			//
			handle_end_of_file(inspector, print_progress, reset_colors, formatter);
			std::cerr << "res = " << res << std::endl;
			throw sinsp_exception(inspector->getlasterr().c_str());
		}

		formatter = (ev->get_type() == PPME_PLUGINEVENT_E ? plugin_evt_formatter : syscall_evt_formatter);

		if (duration_start == 0)
		{
			duration_start = ev->get_ts();
		} else if(duration_to_tot_ns > 0)
		{
			if(ev->get_ts() - duration_start >= duration_to_tot_ns)
			{
				handle_end_of_file(inspector, print_progress, reset_colors, formatter);
				break;
			}
		}
		retval.m_nevts++;

		if(print_progress)
		{
			output_progress(inspector, ev);
		}

		//
		// If there are chisels to run, run them
		//
#ifdef HAS_CHISELS
		if(!g_chisels.empty())
		{
			for(std::vector<sinsp_chisel*>::iterator it = g_chisels.begin(); it != g_chisels.end(); ++it)
			{
				if((*it)->run(ev) == false)
				{
					continue;
				}
			}
		}
		else
#endif
		{
			//
			// If we're supposed to summarize, increase the count for this event
			//
			if(!summary_table.empty())
			{
				uint16_t etype = ev->get_type();

				if(etype == PPME_GENERIC_E)
				{
					sinsp_evt_param *parinfo = ev->get_param(0);
					uint16_t id = *(int16_t *)parinfo->m_val;
					summary_table[PPM_EVENT_MAX + id * 2].m_ncalls++;
				}
				else if(etype == PPME_GENERIC_X)
				{
					sinsp_evt_param *parinfo = ev->get_param(0);
					uint16_t id = *(int16_t *)parinfo->m_val;
					summary_table[PPM_EVENT_MAX + id * 2 + 1].m_ncalls++;
				}
				else
				{
					summary_table[etype].m_ncalls++;
				}
			}

			//
			// When the quiet flag is specified, we don't do any kind of processing other
			// than counting the events.
			//
			if(quiet)
			{
				continue;
			}

			if(!inspector->is_debug_enabled() &&
				ev->get_category() & EC_INTERNAL)
			{
				continue;
			}

			if(display_filter && !display_filter->run(ev))
			{
				continue;
			}

			//
			// Output the line
			//
			if(formatter->tostring(ev, &line))
			{
				std::cout << line << std::endl;
			}
		}

		if(do_flush)
		{
			std::cout << std::flush;
		}
	}
	inspector->stop_capture();
	return retval;
}

#ifndef _WIN32
struct termios g_saved_term_attributes;

void reset_tty_input_mode(void)
{
	tcsetattr(STDIN_FILENO, TCSANOW, &g_saved_term_attributes);
}

void disable_tty_echo() {
	struct termios tattr;

	/* Make sure stdin is a terminal. */
	if (!isatty(STDIN_FILENO))
	{
		return;
	}

	/* Save the terminal attributes so we can restore them later. */
	tcgetattr(STDIN_FILENO, &g_saved_term_attributes);
	atexit(reset_tty_input_mode);

	/* Disable terminal echo */
	tcgetattr(STDIN_FILENO, &tattr);
	tattr.c_lflag &= ~(ICANON|ECHO); /* Clear ICANON and ECHO. */
	tattr.c_cc[VMIN] = 1;
	tattr.c_cc[VTIME] = 0;
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &tattr);
}
#endif

std::string escape_output_format(const std::string& s)
{
    std::stringstream  ss{""};

    for(size_t i = 0; i < s.length(); i++)
    {
        if (s.at(i) == '\\')
        {
            switch(s.at(i + 1))
            {
                case 'n':  ss << "\n"; i++; break;
				case 't':  ss << "\t"; i++; break;
				case 'e':  ss << "\e"; i++; break;
				case '\\': ss << "\\"; i++; break;
                default:   ss << "\\";      break;
            }
        }
        else
        {
            ss << s.at(i);
        }
    }

    return ss.str();
}

//
// ARGUMENT PARSING AND PROGRAM SETUP
//
sysdig_init_res sysdig_init(int argc, char **argv)
{
	sysdig_init_res res;
	sinsp* inspector = NULL;
	std::vector<std::string> infiles;
	std::string outfile;
	int op;
	uint64_t cnt = -1;
	bool quiet = false;
	bool is_filter_display = false;
	bool verbose = false;
	bool list_flds = false;
	bool list_flds_markdown = false;
	std::string list_flds_source = "";
	bool compress = false;
	sinsp_evt::param_fmt event_buffer_format = sinsp_evt::PF_NORMAL;
	sinsp_filter* display_filter = NULL;
	double duration = 1;
	int duration_to_tot = 0;
	captureinfo cinfo;
	std::string output_format;
	std::string output_format_plugin;
	uint32_t snaplen = 0;
	int long_index = 0;
	int32_t n_filterargs = 0;
	bool jflag = false;
	bool unbuf_flag = false;
	bool reset_colors = false;
	bool filter_proclist_flag = false;
	std::string cname;
	std::vector<summary_table_entry> summary_table;
#ifndef MINIMAL_BUILD
	std::string* k8s_api = 0;
	std::string* node_name = 0;
	std::string* k8s_api_cert = 0;
	std::string* mesos_api = 0;
#endif // MINIMAL_BUILD
	bool force_tracers_capture = false;
	std::set<std::string> suppress_comms;
#ifdef HAS_CAPTURE
	std::string cri_socket_path;
#endif
	plugin_utils plugins;
	bool list_plugins = false;
	std::string plugin_config_file = "";
	sinsp_opener opener;

	// These variables are for the cycle_writer engine
	int duration_seconds = 0;
	int rollover_mb = 0;
	int file_limit = 0;
	unsigned long event_limit = 0L;

	static struct option long_options[] =
	{
		{"print-ascii", no_argument, 0, 'A' },
		{"print-base64", no_argument, 0, 'b' },
		{"bpf", optional_argument, 0, 'B' },
#ifdef HAS_CHISELS
		{"chisel", required_argument, 0, 'c' },
		{"list-chisels", no_argument, 0, 0 },
#endif
#ifdef HAS_MODERN_BPF
		{"cpus-for-each-buffer", required_argument, 0, 0 },
#endif
#ifdef HAS_CAPTURE
		{"cri", required_argument, 0, 0 },
		{"cri-timeout", required_argument, 0, 0 },
#endif
		{"displayflt", no_argument, 0, 'd' },
		{"debug", no_argument, 0, 'D'},
		{"exclude-users", no_argument, 0, 'E' },
		{"event-limit", required_argument, 0, 'e'},
		{"fatfile", no_argument, 0, 'F'},
		{"filter-proclist", no_argument, 0, 0 },
		{"gvisor-config", required_argument, 0, 'g'},
		{"gvisor-generate-config", optional_argument, 0, 0},
		{"gvisor-root", required_argument, 0, 0},
		{"seconds", required_argument, 0, 'G' },
		{"help", no_argument, 0, 'h' },
		{"input", required_argument, 0, 'I' },
#ifdef HAS_CHISELS
		{"chisel-info", required_argument, 0, 'i' },
#endif
		{"file-size", required_argument, 0, 'C' },
		{"json", no_argument, 0, 'j' },
#ifndef MINIMAL_BUILD
		{"k8s-api", required_argument, 0, 'k'},
		{"node-name", required_argument, 0, 'N'},
		{"k8s-api-cert", required_argument, 0, 'K' },
#endif // MINIMAL_BUILD
		{"large-environment", no_argument, 0, 0 },
		{"list", optional_argument, 0, 'l' },
		{"list-events", no_argument, 0, 'L' },
		{"list-markdown", optional_argument, 0, 0 },
		{"libs-version", no_argument, 0, 0},
		{"log-level", required_argument, 0, 0 },
#ifndef MINIMAL_BUILD
		{"mesos-api", required_argument, 0, 'm'},
#endif // MINIMAL_BUILD
#ifdef HAS_MODERN_BPF
		{"modern-bpf", no_argument, 0, 0 },
#endif
		{"numevents", required_argument, 0, 'n' },
		{"page-faults", no_argument, 0, 0 },
		{"plugin", required_argument, 0, 'H' },
		{"plugin-config-file", required_argument, 0, 0},
		{"plugin-info", required_argument, 0, 0 },
		{"progress", required_argument, 0, 'P' },
		{"print", required_argument, 0, 'p' },
		{"quiet", no_argument, 0, 'q' },
		{"resolve-ports", no_argument, 0, 'R'},
		{"readfile", required_argument, 0, 'r' },
		{"snaplen", required_argument, 0, 's' },
		{"summary", no_argument, 0, 'S' },
		{"suppress-comm", required_argument, 0, 'U' },
		{"udig", required_argument, 0, 'u' },
		{"timetype", required_argument, 0, 't' },
		{"force-tracers-capture", required_argument, 0, 'T'},
		{"unbuffered", no_argument, 0, 0 },
		{"verbose", no_argument, 0, 'v' },
		{"version", no_argument, 0, 0 },
		{"writefile", required_argument, 0, 'w' },
		{"limit", required_argument, 0, 'W' },
		{"print-hex", no_argument, 0, 'x'},
		{"print-hex-ascii", no_argument, 0, 'X'},
		{"compress", no_argument, 0, 'z' },
		{0, 0, 0, 0}
	};

#ifndef _WIN32
	if (isatty(fileno(stdout)))
	{
		output_format = R"(*%evt.num %evt.outputtime %evt.cpu \e[01;32m%proc.name\e[00m (\e[01;36m%proc.pid\e[00m.%thread.tid) %evt.dir \e[01;34m%evt.type\e[00m %evt.info)";
		output_format_plugin = R"(*%evt.num %evt.datetime.s [\e[01;32m%evt.pluginname\e[00m] %evt.plugininfo)";
	}
	else
#endif
	{
		output_format = "*%evt.num %evt.outputtime %evt.cpu %proc.name (%thread.tid) %evt.dir %evt.type %evt.info";
		output_format_plugin = "*%evt.num %evt.datetime.s [%evt.pluginname] %evt.plugininfo";
	}

	try
	{
		inspector = new sinsp();
		inspector->set_hostname_and_port_resolution_mode(false);

#ifdef HAS_CHISELS
		add_chisel_dirs(inspector);
#endif
		plugins.add_directory(SYSDIG_PLUGINS_DIR);
		plugins.read_plugins_from_dirs(inspector);

		//
		// Parse the args
		//
		while((op = getopt_long(argc, argv,
                                        "AbB::c:"
                                        "C:"
                                        "dDEe:F"
                                        "g:G:"
                                        "hH:I:i:jk:K:lLm:M:n:Pp:qRr:Ss:t:TU:uv"
                                        "W:"
                                        "w:xXz", long_options, &long_index)) != -1)
		{
			switch(op)
			{
			case 'A':
				if(event_buffer_format != sinsp_evt::PF_NORMAL)
				{
					fprintf(stderr, "you cannot specify more than one output format\n");
					delete inspector;
					return sysdig_init_res(EXIT_SUCCESS);
				}

				event_buffer_format = sinsp_evt::PF_EOLS;
				break;
			case 'b':
				if(event_buffer_format != sinsp_evt::PF_NORMAL)
				{
					fprintf(stderr, "you cannot specify more than one output format\n");
					delete inspector;
					return sysdig_init_res(EXIT_SUCCESS);
				}

				event_buffer_format = sinsp_evt::PF_BASE64;
				break;
			case 'B':
			{
				opener.bpf.enabled = true;
				if(optarg)
				{
					opener.bpf.probe = optarg;
				}
				break;
			}
#ifdef HAS_CHISELS
			case 'c':
				{
					std::string chisel = optarg;
					if(chisel == "l")
					{
						std::vector<chisel_desc> chlist;
						sinsp_chisel::get_chisel_list(&chlist);
						list_chisels(&chlist, true);
						delete inspector;
						return sysdig_init_res(EXIT_SUCCESS);
					}

					sinsp_chisel* ch = new sinsp_chisel(inspector, chisel);
					parse_chisel_args(ch, inspector, optind, argc, argv, &n_filterargs);
					g_chisels.push_back(ch);
				}
#endif
				break;

			// File-size
			case 'C':
				rollover_mb = atoi(optarg);
				if(rollover_mb <= 0)
				{
					throw sinsp_exception(std::string("invalid file size") + optarg);
					res.m_res = EXIT_FAILURE;
					goto exit;
				}
				break;
			case 'D':
				inspector->set_debug_mode(true);
				inspector->set_internal_events_mode(true);
				inspector->set_log_stderr();
				break;
			case 'E':
				inspector->set_import_users(false);
				break;
			case 'e':
				event_limit = strtoul(optarg, NULL, 0);
				if(event_limit <= 0)
				{
					throw sinsp_exception(std::string("invalid parameter 'number of events' ") + optarg);
					res.m_res = EXIT_FAILURE;
					goto exit;
				}
				break;
			case 'F':
				inspector->set_fatfile_dump_mode(true);
				break;
			// Number of seconds between roll-over
			case 'g':
				opener.gvisor.enabled = true;
				if(optarg)
				{
					opener.gvisor.config = optarg;
				}
				break;
			case 'G':
				duration_seconds = atoi(optarg);
				if(duration_seconds <= 0)
				{
					throw sinsp_exception(std::string("invalid duration") + optarg);
					res.m_res = EXIT_FAILURE;
					goto exit;
				}
				break;
			case 'H':
				{
					std::string pluginname = optarg;
					size_t cpos = pluginname.find(':');
					std::string pgname = pluginname;
					std::string pginitconf;
					// Extract init config from string if present
					if(cpos != std::string::npos)
					{
						pgname = pluginname.substr(0, cpos);
						pginitconf = pluginname.substr(cpos + 1);
					}
					plugins.load_plugin(inspector, pgname);
					plugins.config_plugin(inspector, pgname, pginitconf);
					break;
				}
			case 'I':
				{
					std::string inputname = optarg;
					if(inputname == "l")
					{
						list_plugins = true;
						break;
					}

					size_t cpos = inputname.find(':');
					std::string pgname = inputname;
					std::string pgpars;
					// Extract open params from string if present
					if(cpos != std::string::npos)
					{
						pgname = inputname.substr(0, cpos);
						pgpars = inputname.substr(cpos + 1);
					}
					plugins.select_input_plugin(inspector, pgname, pgpars);
					g_plugin_input = true;
					opener.plugin.enabled = true;
				}
				break;
#ifdef HAS_CHISELS
			// --chisel-info and -i
			case 'i':
				{
					cname = optarg;
					std::vector<chisel_desc> chlist;

					sinsp_chisel::get_chisel_list(&chlist);

					for(uint32_t j = 0; j < chlist.size(); j++)
					{
						if(chlist[j].m_name == cname)
						{
							print_chisel_info(&chlist[j]);
							delete inspector;
							return sysdig_init_res(EXIT_SUCCESS);
						}
					}

					throw sinsp_exception("chisel " + cname + " not found - use -cl to list them.");
				}
				break;
#endif
			case 'd':
				is_filter_display = true;
				break;
			case 'j':
				//
				// set the json flag to 1 for now, the data format will depend from the print format parameters
				//
				jflag = true;
				break;
#ifndef MINIMAL_BUILD
			case 'k':
				k8s_api = new std::string(optarg);
				break;
			case 'N':
				node_name = new std::string(optarg);
				break;
			case 'K':
				k8s_api_cert = new std::string(optarg);
				break;
#endif // MINIMAL_BUILD
			case 'h':
				usage();
				delete inspector;
				return sysdig_init_res(EXIT_SUCCESS);
			case 'l':
				list_flds = true;
				if (optarg)
				{
					list_flds_source = optarg;
				}
				break;
			case 'L':
				// todo(jasondellaluce): support CLI for printing in markdown too
				print_supported_events(inspector, false);
				delete inspector;
				return sysdig_init_res(EXIT_SUCCESS);
#ifndef MINIMAL_BUILD
			case 'm':
				mesos_api = new std::string(optarg);
				break;
#endif // MINIMAL_BUILD
			case 'M':
				duration_to_tot = atoi(optarg);
				if(duration_to_tot <= 0)
				{
					throw sinsp_exception(std::string("invalid duration") + optarg);
					res.m_res = EXIT_FAILURE;
					goto exit;
				}
				break;
			case 'n':
				try
				{
					cnt = sinsp_numparser::parseu64(optarg);
				}
				catch(...)
				{
					throw sinsp_exception("can't parse the -n argument, make sure it's a number");
				}

				if(cnt <= 0)
				{
					throw sinsp_exception(std::string("invalid event count ") + optarg);
					res.m_res = EXIT_FAILURE;
					goto exit;
				}
				break;
			case 'P':
				opener.options.print_progress = true;
				break;
			case 'p':
				if(std::string(optarg) == "p")
				{
					// -pp shows the default output format, useful if the user wants to tweak it.
					printf("%s\n", output_format.c_str());
					delete inspector;
					return sysdig_init_res(EXIT_SUCCESS);
				}
				else if(std::string(optarg) == "c" || std::string(optarg) == "container")
				{
					output_format = "*%evt.num %evt.outputtime %evt.cpu %container.name (%container.id) %proc.name (%thread.tid:%thread.vtid) %evt.dir %evt.type %evt.info";

					// This enables chisels to determine if they should print container information
					if(inspector != NULL)
					{
						inspector->set_print_container_data(true);
					}
				}
				else if(std::string(optarg) == "k" || std::string(optarg) == "kubernetes")
				{
					output_format = "*%evt.num %evt.outputtime %evt.cpu %k8s.pod.name (%container.id) %proc.name (%thread.tid:%thread.vtid) %evt.dir %evt.type %evt.info";

					// This enables chisels to determine if they should print container information
					if(inspector != NULL)
					{
						inspector->set_print_container_data(true);
					}
				}
				else if(std::string(optarg) == "m" || std::string(optarg) == "mesos")
				{
					output_format = "*%evt.num %evt.outputtime %evt.cpu %mesos.task.name (%container.id) %proc.name (%thread.tid:%thread.vtid) %evt.dir %evt.type %evt.info";

					// This enables chisels to determine if they should print container information
					if(inspector != NULL)
					{
						inspector->set_print_container_data(true);
					}
				}
				else
				{
					output_format = optarg;
					output_format_plugin = optarg;
				}

				break;
			case 'q':
				quiet = true;
				break;
			case 'R':
				inspector->set_hostname_and_port_resolution_mode(true);
				break;
			case 'r':
				infiles.emplace_back(optarg);
#ifndef MINIMAL_BUILD
				k8s_api = new std::string();
				mesos_api = new std::string();
#endif // MINIMAL_BUILD
				break;
			case 'S':
				for(uint32_t j = 0; j < PPM_EVENT_MAX; j++)
				{
					summary_table.push_back(summary_table_entry(j, false));
				}

				for(uint32_t j = 0; j < PPM_SC_MAX * 2; j++)
				{
					summary_table.push_back(summary_table_entry(j, true));
				}

				break;
			case 's':
				snaplen = atoi(optarg);
				break;
			case 't':
				{
					std::string tms(optarg);

					if(tms == "h" || tms == "a" || tms == "r" || tms == "d" || tms == "D")
					{
						inspector->set_time_output_mode(tms.c_str()[0]);
					}
					else
					{
						fprintf(stderr, "invalid modifier for flag -t\n");
						delete inspector;
						return sysdig_init_res(EXIT_FAILURE);
					}
				}
				break;
			case 'T':
				force_tracers_capture = true;
				break;
			case 'U':
				suppress_comms.insert(std::string(optarg));
				break;
			case 'u':
				opener.udig.enabled = true;
				break;
			case 'v':
				verbose = true;
				break;
			case 'w':
				outfile = optarg;
				quiet = true;
				break;

			// Number of capture files to cycle through
			case 'W':
				file_limit = atoi(optarg);
				if(file_limit <= 0)
				{
					throw sinsp_exception(std::string("invalid file limit") + optarg);
					res.m_res = EXIT_FAILURE;
					goto exit;
				}
				break;

			case 'x':
				if(event_buffer_format != sinsp_evt::PF_NORMAL)
				{
					fprintf(stderr, "you cannot specify more than one output format\n");
					delete inspector;
					return sysdig_init_res(EXIT_FAILURE);
				}

				event_buffer_format = sinsp_evt::PF_HEX;
				break;
			case 'X':
				if(event_buffer_format != sinsp_evt::PF_NORMAL)
				{
					fprintf(stderr, "you cannot specify more than one output format\n");
					delete inspector;
					return sysdig_init_res(EXIT_FAILURE);
				}

				event_buffer_format = sinsp_evt::PF_HEXASCII;
				break;
			case 'z':
				compress = true;
				break;
			case 0:
				{
					std::string optname = std::string(long_options[long_index].name);
					if (long_options[long_index].flag != 0) {
						break;
					}
					if (optname == "version") {
						printf("sysdig version %s\n", SYSDIG_VERSION);
						delete inspector;
						return sysdig_init_res(EXIT_SUCCESS);
					}
					else if (optname == "libs-version") {
						printf("falcosecurity/libs version %s\n", FALCOSECURITY_LIBS_VERSION);
						delete inspector;
						return sysdig_init_res(EXIT_SUCCESS);
					}
					else if (optname == "log-level") {
						if (std::string(optarg) == "fatal") {
							inspector->set_min_log_severity(sinsp_logger::SEV_FATAL);
						}
						else if (std::string(optarg) == "critical") {
							inspector->set_min_log_severity(sinsp_logger::SEV_CRITICAL);
						}
						else if (std::string(optarg) == "error") {
							inspector->set_min_log_severity(sinsp_logger::SEV_ERROR);
						}
						else if (std::string(optarg) == "warning") {
							inspector->set_min_log_severity(sinsp_logger::SEV_WARNING);
						}
						else if (std::string(optarg) == "notice") {
							inspector->set_min_log_severity(sinsp_logger::SEV_NOTICE);
						}
						else if (std::string(optarg) == "info") {
							inspector->set_min_log_severity(sinsp_logger::SEV_INFO);
						}
						else if (std::string(optarg) == "debug") {
							inspector->set_min_log_severity(sinsp_logger::SEV_DEBUG);
						}
						else if (std::string(optarg) == "trace") {
							inspector->set_min_log_severity(sinsp_logger::SEV_TRACE);
						} else {
							fprintf(stderr, "invalid log level %s\n", optarg);
							delete inspector;
							return sysdig_init_res(EXIT_FAILURE);
						}
						g_logger.add_stdout_log();
					}
					else if (optname == "list-chisels") {
						std::vector<chisel_desc> chlist;
						sinsp_chisel::get_chisel_list(&chlist);
						list_chisels(&chlist, true);
						delete inspector;
						return sysdig_init_res(EXIT_SUCCESS);
					}
#ifdef HAS_MODERN_BPF
					else if(optname == "cpus-for-each-buffer")
					{
						opener.bpf.cpus_for_each_syscall_buffer = sinsp_numparser::parsed16(optarg);
					}
#endif
#ifdef HAS_CAPTURE
					else if (optname == "cri") {
						cri_socket_path = optarg;
					}
					else if (optname == "cri-timeout") {
						inspector->set_cri_timeout(sinsp_numparser::parsed64(optarg));
					}
#endif
					else if (optname == "unbuffered") {
						unbuf_flag = true;
					}

					else if (optname == "filter-proclist") {
						filter_proclist_flag = true;
					}

					else if (optname == "gvisor-generate-config") {
						std::string socket_path;
						if (optarg)
						{
							socket_path = std::string(optarg);
						}
						std::string generated_config = inspector->generate_gvisor_config(socket_path);
						printf("%s", generated_config.c_str());
						return sysdig_init_res(EXIT_SUCCESS);
					}

					else if (optname == "gvisor_root")
					{
						if (optarg)
						{
							opener.gvisor.root = std::string(optarg);
						}
					}

					else if (optname == "large-environment") {
						inspector->set_large_envs(true);
					}

					else if (optname == "list-markdown") {
						list_flds = true;
						list_flds_markdown = true;
						if (optarg)
						{
							list_flds_source = optarg;
						}
					}

#ifdef HAS_MODERN_BPF
					else if(optname == "modern-bpf")
					{
						opener.bpf.enabled = true;
						opener.bpf.modern = true;
					}
#endif

					else if(optname == "plugin-config-file") {
						plugin_config_file = optarg;
						plugins.load_plugins_from_conf_file(inspector, plugin_config_file, false);
					}

					else if (optname == "page-faults") {
						opener.options.page_faults = true;
					}

					else if (optname == "plugin-info")
					{
						auto name = std::string(optarg);
						plugins.print_plugin_info(inspector, name);
						delete inspector;
						return sysdig_init_res(EXIT_SUCCESS);
					}
				}
				break;
			// getopt_long : '?' for an ambiguous match or an extraneous parameter
			case '?':
				delete inspector;
				return sysdig_init_res(EXIT_FAILURE);
				break;
			default:
				break;
			}
		}

		// given the CLI options, we finish loading and initializing plugins.
		// if no plugin has been specified as input with -I, we try to
		// reload the config file (if present), and set the input plugin 
		// depending on its content. In this way, -I has priority no matter
		// what the CLI option order is, and the config file can also be used
		// for the purposes of configuring plugins without defining the input.
		if (!opener.plugin.enabled && !plugin_config_file.empty())
		{
			// reload the file but by setting the plugin input, if present
			plugins.load_plugins_from_conf_file(inspector, plugin_config_file, true);

			// set a flag if our event sourc input is a plugin-defined one
			opener.plugin.enabled = plugins.has_input_plugin();
			g_plugin_input = opener.plugin.enabled;
		}

		// all plugins have been loaded and configured so now we initialize them
		plugins.init_loaded_plugins(inspector);
		
		if (list_plugins)
		{
			plugins.print_plugin_info_list(inspector);
			printf("More detailed info about individual plugins can be printed with the --plugin-info option:\n");
			printf(" Detailed info about a single plugin\n");
			printf("   $ sysdig --plugin-info=dummy\n\n");
			printf(" Detailed info about a single plugin with a given configuration\n");
			printf("   $ sysdig -H dummy:'{\"jitter\":50}' --plugin-info=dummy\n\n");
			delete inspector;
			return sysdig_init_res(EXIT_SUCCESS);
		}

#ifdef HAS_CAPTURE
		if(!cri_socket_path.empty())
		{
			inspector->set_cri_socket_path(cri_socket_path);
		}
#endif

		if (opener.plugin.enabled)
		{
			opener.plugin.name = plugins.input_plugin_name();
			opener.plugin.params = plugins.input_plugin_params();
		}
		
		if(!opener.bpf.enabled)
		{
			const char *probe = getenv("SYSDIG_BPF_PROBE");
			if (probe)
			{
				opener.bpf.enabled = true;
				opener.bpf.probe = probe;
			}
		}

		//
		// If we are dumping events to file, enable progress printing so we can give
		// feedback to the user
		//
		if(!outfile.empty() && (!infiles.empty() || opener.plugin.enabled))
		{
			opener.options.print_progress = true;
		}

		//
		// If -j was specified the event_buffer_format must be rewritten to account for it
		//
		if(jflag)
		{
			switch (event_buffer_format)
			{
				case sinsp_evt::PF_NORMAL:
					event_buffer_format = sinsp_evt::PF_JSON;
					break;
				case sinsp_evt::PF_EOLS:
					event_buffer_format = sinsp_evt::PF_JSONEOLS;
					break;
				case sinsp_evt::PF_HEX:
					event_buffer_format = sinsp_evt::PF_JSONHEX;
					break;
				case sinsp_evt::PF_HEXASCII:
					event_buffer_format = sinsp_evt::PF_JSONHEXASCII;
					break;
				case sinsp_evt::PF_BASE64:
					event_buffer_format = sinsp_evt::PF_JSONBASE64;
					break;
				default:
					// do nothing
					break;
			}
		}

		inspector->set_buffer_format(event_buffer_format);

		//
		// If -l was specified, print the fields and exit
		//
		if(list_flds)
		{
			print_supported_fields(inspector, plugins, list_flds_source, verbose, list_flds_markdown);
			res.m_res = EXIT_SUCCESS;
			goto exit;
		}

		std::string filter;

		//
		// the filter is at the end of the command line
		//
		if(optind + n_filterargs < argc)
		{
			for(int32_t j = optind + n_filterargs; j < argc; j++)
			{
				filter += argv[j];
				if(j < argc - 1)
				{
					filter += " ";
				}
			}

			if(is_filter_display)
			{
				try
				{
					sinsp_filter_compiler compiler(inspector, filter);
					display_filter = compiler.compile();
				}
				catch (sinsp_exception& e)
				{
					const char* errpos = strstr(e.what(), g_unknown_field_err);
					if (errpos != NULL)
					{
						const char* field = errpos + strlen(g_unknown_field_err);
						plugins.print_field_extraction_support(inspector, field);
					}
					throw e;
				}
			}
		}

		if(signal(SIGINT, signal_callback) == SIG_ERR)
		{
			fprintf(stderr, "An error occurred while setting SIGINT signal handler.\n");
			res.m_res = EXIT_FAILURE;
			goto exit;
		}

		if(signal(SIGTERM, signal_callback) == SIG_ERR)
		{
			fprintf(stderr, "An error occurred while setting SIGTERM signal handler.\n");
			res.m_res = EXIT_FAILURE;
			goto exit;
		}

		output_format = escape_output_format(output_format);
		if (output_format.find("\e") != std::string::npos)
		{
			reset_colors = true;
		}

		output_format_plugin = escape_output_format(output_format_plugin);
		if (output_format_plugin.find("\e") != std::string::npos)
		{
			reset_colors = true;
		}

#ifndef _WIN32
		if(signal(SIGALRM, signal_callback) == SIG_ERR)
		{
			fprintf(stderr, "An error occurred while setting SIGALRM signal handler.\n");
			res.m_res = EXIT_FAILURE;
			goto exit;
		}
#endif

		//
		// Create the event formatter
		//
		sinsp_evt_formatter syscall_evt_formatter(inspector, output_format);

		sinsp_evt_formatter plugin_evt_formatter(inspector, output_format_plugin);

		//
		// Set output buffers len
		//
		if(!verbose && g_chisels.empty())
		{
			inspector->set_max_evt_output_len(80);
		}

		//
		// Determine if we need to filter when dumping to file
		//
		if(filter_proclist_flag)
		{
			if(!filter.empty())
			{
				if(infiles.empty())
				{
					fprintf(stderr, "--filter-proclist not supported with live captures.\n");
					res.m_res = EXIT_FAILURE;
					goto exit;
				}

				inspector->filter_proc_table_when_saving(true);
			}
			else
			{
				fprintf(stderr, "you must specify a filter if you use --filter-proclist.\n");
				res.m_res = EXIT_FAILURE;
				goto exit;
			}
		}

		for(uint32_t j = 0; j < infiles.size() || infiles.empty(); j++)
		{
			if(!filter.empty() && !is_filter_display)
			{
				try
				{
					inspector->set_filter(filter);
				}
				catch (sinsp_exception& e)
				{
					const char* errpos = strstr(e.what(), g_unknown_field_err);
					if (errpos != NULL)
					{
						const char* field = errpos + strlen(g_unknown_field_err);
						plugins.print_field_extraction_support(inspector, field);
					}
					throw e;
				}
			}

			// Suppress any comms specified via -U. We
			// need to do this *before* opening the
			// inspector, as that reads the process list.
			for(auto &comm : suppress_comms)
			{
				if (!inspector->suppress_events_comm(comm))
				{
					fprintf(stderr, "Could not add %s to the set of suppressed comms--did you specify more than %d values?\n",
						comm.c_str(),
						SCAP_MAX_SUPPRESSED_COMMS);
					res.m_res = EXIT_FAILURE;
					goto exit;
				}
			}

			//
			// Launch the capture
			//
			if(!infiles.empty())
			{
				initialize_chisels();
				opener.savefile.enabled = true;
				opener.savefile.path = infiles[j];
				opener.open(inspector);
			}
			else
			{
				if(j > 0)
				{
					break;
				}

				initialize_chisels();
				opener.open(inspector);
			}

			//
			// If required, set the snaplen
			//
			if(snaplen != 0)
			{
				inspector->set_snaplen(snaplen);
			}

			//
			// If required, tell the driver to enable tracers capture
			//
			if(force_tracers_capture)
			{
				inspector->enable_tracers_capture();
			}

			duration = ((double)clock()) / CLOCKS_PER_SEC;

			if(outfile != "")
			{
				inspector->setup_cycle_writer(outfile, rollover_mb, duration_seconds, file_limit, event_limit, compress);
				inspector->autodump_next_file();
			}

			//
			// Notify the chisels that the capture is starting
			//
			chisels_on_capture_start();

#ifndef MINIMAL_BUILD
			//
			// run k8s, if required
			//
			if(k8s_api)
			{
				if(!k8s_api_cert)
				{
					if(char* k8s_cert_env = getenv("SYSDIG_K8S_API_CERT"))
					{
						k8s_api_cert = new std::string(k8s_cert_env);
					}
				}
				inspector->init_k8s_client(k8s_api, k8s_api_cert, node_name, verbose);
				k8s_api = 0;
				k8s_api_cert = 0;
			}
			else if(char* k8s_api_env = getenv("SYSDIG_K8S_API"))
			{
				if(k8s_api_env != NULL)
				{
					if(!k8s_api_cert)
					{
						if(char* k8s_cert_env = getenv("SYSDIG_K8S_API_CERT"))
						{
							k8s_api_cert = new std::string(k8s_cert_env);
						}
					}
					k8s_api = new std::string(k8s_api_env);
					inspector->init_k8s_client(k8s_api, k8s_api_cert, node_name, verbose);
				}
				else
				{
					delete k8s_api;
					delete k8s_api_cert;
				}
				k8s_api = 0;
				k8s_api_cert = 0;
			}

			//
			// run mesos, if required
			//
			if(mesos_api)
			{
				inspector->init_mesos_client(mesos_api, verbose);
			}
			else if(char* mesos_api_env = getenv("SYSDIG_MESOS_API"))
			{
				if(mesos_api_env != NULL)
				{
					mesos_api = new std::string(mesos_api_env);
					inspector->init_mesos_client(mesos_api, verbose);
				}
			}
			delete mesos_api;
			mesos_api = 0;
#endif
#ifndef _WIN32
			// Sysdig does not accept user input during the inspect loop
			// If the user stops the program with Ctrl-C disabling input would prevent the echoed ^C
			// from messing up the output and possibly the shell line after program termination.
			disable_tty_echo();
#endif
			cinfo = do_inspect(inspector,
				cnt,
				uint64_t(duration_to_tot*ONE_SECOND_IN_NS),
				quiet,
				jflag,
				unbuf_flag,
				reset_colors,
				opener.options.print_progress,
				display_filter,
				summary_table,
				&syscall_evt_formatter,
				&plugin_evt_formatter);

			duration = ((double)clock()) / CLOCKS_PER_SEC - duration;

			scap_stats cstats;
			inspector->get_capture_stats(&cstats);

			if(verbose)
			{
				fprintf(stderr, "Driver Events:%" PRIu64 "\nDriver Drops:%" PRIu64 "\nSuppressed by Comm:%" PRIu64 "\n",
					cstats.n_evts,
					cstats.n_drops,
					cstats.n_suppressed);

				fprintf(stderr, "Elapsed time: %.3lf, Captured Events: %" PRIu64 ", %.2lf eps\n",
					duration,
					cinfo.m_nevts,
					(double)cinfo.m_nevts / duration);
			}

			//
			// Done. Close the inspector.
			//
			inspector->close();
		}
	}
	catch(const chisel_capture_interrupt_exception&)
	{
		handle_end_of_file(NULL, opener.options.print_progress, reset_colors);
	}
	catch(const scap_open_exception& e)
	{
		std::cerr << e.what() << std::endl;
		handle_end_of_file(NULL, opener.options.print_progress, reset_colors);
		res.m_res = e.scap_rc();
	}
	catch(const sinsp_exception& e)
	{
		std::cerr << e.what() << std::endl;
		handle_end_of_file(NULL, opener.options.print_progress, reset_colors);
		res.m_res = EXIT_FAILURE;
	}
	catch (const std::runtime_error& e)
	{
		std::cerr << e.what() << std::endl;
		handle_end_of_file(NULL, opener.options.print_progress, reset_colors);
		res.m_res = EXIT_FAILURE;
	}
	catch(...)
	{
		handle_end_of_file(NULL, opener.options.print_progress, reset_colors);
		res.m_res = EXIT_FAILURE;
	}

exit:
	//
	// If any of the chisels is requesting another run,
	//
	for(std::vector<sinsp_chisel*>::iterator it = g_chisels.begin();
		it != g_chisels.end(); ++it)
	{
		std::string na;
		if((*it)->get_nextrun_args(&na))
		{
			res.m_next_run_args = split_nextrun_args(na);
		}
	}

	//
	// If summary table is not empty, sort and print it
	//
	if(!summary_table.empty())
	{
		print_summary_table(inspector, summary_table, 100);
	}

	//
	// Free all the stuff that was allocated
	//
	free_chisels();

	if(inspector)
	{
		delete inspector;
	}

	if(display_filter)
	{
		delete display_filter;
	}

	return res;
}

//
// MAIN
//
int main(int argc, char **argv)
{
	sysdig_init_res res;

	res = sysdig_init(argc, argv);

	//
	// Check if a second run has been requested
	//
	if(res.m_next_run_args.size() != 0)
	{
		optind = 1;
		opterr = 1;
		optopt = '?';

		int newargc = (int)res.m_next_run_args.size() + 1;
		std::vector<char*> newargv;

		newargv.push_back(argv[0]);

		for(int32_t j = 1; j < newargc; j++)
		{
			newargv.push_back((char*)res.m_next_run_args[j - 1].c_str());
		}

		res = sysdig_init(newargc, &(newargv[0]));
	}
#ifdef _WIN32
	_CrtDumpMemoryLeaks();
#endif

	return res.m_res;
}
