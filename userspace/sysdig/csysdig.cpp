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
#include <cstring>

#include <libsinsp/sinsp.h>
#include "plugin_manager.h"
#ifdef HAS_CAPTURE
#ifndef WIN32
#include "driver_config.h"
#endif // WIN32
#endif // HAS_CAPTURE
#include "sysdig.h"
#ifdef HAS_CHISELS
#include <chisel/chisel.h>
#include <chisel/chisel_utils.h>
#endif
#include <chisel/chisel_table.h>
#include <libsinsp/utils.h>
#include "utils/plugin_utils.h"
#include "utils/sinsp_opener.h"
#include "utils/supported_fields.h"
#include "filterchecks/sinsp_filtercheck_syslog.h"

#include <CLI/CLI.hpp>

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#include <term.h>
#endif

#include "cursescomponents.h"
#include "cursestable.h"
#include "cursesui.h"
#include <libsinsp/scap_open_exception.h>
#include <chisel/chisel_capture_interrupt_exception.h>

#define MOUSE_CAPABLE_TERM "xterm-1003"
#define MOUSE_CAPABLE_TERM_COMPAT "xterm-1002"

static bool g_terminate = false;
static bool g_plugin_input = false;
static void usage();

//
// Command-line options structure (for CLI11 refactoring)
//
struct csysdig_options {
	// Common options
	bool help = false;
	bool version = false;
	bool exclude_users = false;
	bool resolve_ports = false;
	bool list_fields = false;
	bool list_views = false;

	// Display format options
	bool print_ascii = false;
	bool print_hex_ascii = false;
	bool print_containers = false;
	bool json = false;
	bool raw = false;
	bool interactive = false;

	// Capture options
	std::string bpf_probe;
	bool modern_bpf = false;
	int cpus_for_each_buffer = 0;
	bool page_faults = false;
	bool large_environment = false;

	// I/O options
	std::vector<std::string> read_files;
	int snaplen = 0;
	uint64_t num_events = std::numeric_limits<uint64_t>::max();

	// UI options
	uint64_t refresh_interval_ms = 2000;  // Default 2 seconds
	std::string view_id;
	std::string logfile;
	bool force_term_compat = false;
	int32_t json_first_row = 0;
	int32_t json_last_row = 0;
	int32_t sorting_col = -1;

	// Remaining positional args (filter)
	std::vector<std::string> filter_args;
};

static bool is_short_option_with_value_csysdig(const std::string& arg, const std::string& opts)
{
	return arg.size() > 2 && arg[0] == '-' && arg[1] != '-' && opts.find(arg[1]) != std::string::npos;
}

static std::vector<std::string> normalize_csysdig_argv(int argc, char** argv)
{
	std::vector<std::string> normalized;
	normalized.reserve(argc);
	if(argc > 0)
	{
		normalized.emplace_back(argv[0]);
	}

	for(int i = 1; i < argc; ++i)
	{
		std::string arg = argv[i];
		if(is_short_option_with_value_csysdig(arg, "Bdnprsv"))
		{
			normalized.emplace_back(arg.substr(0, 2));
			normalized.emplace_back(arg.substr(2));
			continue;
		}

		normalized.emplace_back(std::move(arg));
	}

	return normalized;
}

static std::vector<char*> argv_ptrs_csysdig(std::vector<std::string>& args)
{
	std::vector<char*> res;
	res.reserve(args.size());
	for(auto& arg : args)
	{
		res.push_back(arg.data());
	}
	return res;
}

static int count_enabled_formats(const csysdig_options& opts)
{
	return (opts.print_ascii ? 1 : 0) +
		(opts.print_hex_ascii ? 1 : 0);
}

//
// Helper functions
//
static void signal_callback(int signal)
{
	if(g_plugin_input)
	{
		//
		// Input plugins can get stuck at any point.
		// When we are using one, check again in few seconds and force a quit
		// if we are stuck.
		//
		if(g_terminate == true)
		{
			exit(0);
		}
		else
		{
			g_terminate = true;
#ifndef _WIN32
			alarm(2);
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
"csysdig version " SYSDIG_VERSION "\n"
"Usage: csysdig [options] [filter]\n\n"
"Options:\n"
" -A, --print-ascii  When emitting JSON, only print the text portion of data buffers, and echo\n"
"                    end-of-lines. This is useful to only display human-readable\n"
"                    data.\n"
#ifdef HAS_MODERN_BPF
" --modern-bpf\n"
"                    Enable live capture using the modern BPF probe instead of the kernel module.\n"
#endif
" -B<bpf_probe>, --bpf=<bpf_probe>\n"
"                    Enable live capture using the specified BPF probe instead of the kernel module.\n"
"                    The BPF probe can also be specified via the environment variable\n"
"                    SYSDIG_BPF_PROBE. If <bpf_probe> is left empty, sysdig will\n"
"                    try to load one from the scap-driver-loader script.\n"
#ifdef HAS_MODERN_BPF
"  --cpus-for-each-buffer <cpus_num>\n"
"                    Please note this config regards only the modern BPF probe.\n"
"                    How many CPUs you want to assign to a single syscall buffer (ring buffer).\n"
"                    By default, every syscall buffer is associated to 2 CPUs, so the mapping is\n"
"                    1:2. The modern BPF probe allows you to choose different mappings, for\n"
"                    example, 1:1 would mean a syscall buffer for each CPU.\n"
#endif
" -d <period>, --delay=<period>\n"
"                    Set the delay between updates, in milliseconds. This works\n"
"                    similarly to the -d option in top.\n"
" -E, --exclude-users\n"
"                    Don't create the user/group tables by querying the OS when\n"
"                    sysdig starts. This also means that no user or group info\n"
"                    will be written to the tracefile by the -w flag.\n"
"                    The user/group tables are necessary to use filter fields\n"
"                    like user.name or group.name. However, creating them can\n"
"                    increase sysdig's startup time. Moreover, they contain\n"
"                    information that could be privacy sensitive.\n"
" --force-term-compat\n"
"                    Try to configure simple terminal settings (xterm-1002) that work\n"
"                    better with terminals like putty. Try to use this flag if you experience\n"
"                    terminal issues like the mouse not working.\n"
" -h, --help         Print this page\n"
" -l, --list         List all the fields that can be used in views.\n"
" --large-environment\n"
"                    Support environments larger than 4KiB\n"
"                    When the environment is larger than 4KiB, load the whole\n"
"                    environment from /proc instead of truncating to the first 4KiB\n"
"                    This may fail for short-lived processes and in that case\n"
"                    the truncated environment is used instead.\n"
" --logfile=<file>\n"
"                    Print program logs into the given file.\n"
" -n <num>, --numevents=<num>\n"
"                    Stop capturing after <num> events\n"
" --page-faults      Capture user/kernel major/minor page faults\n"
" -pc, -pcontainer\n"
"                    Instruct csysdig to use a container-friendly format in its\n"
"                    views.\n"
"                    This will cause several of the views to contain additional\n"
"                    container-related columns.\n"
" -R                 Resolve port numbers to names.\n"
" -r <readfile>, --read=<readfile>\n"
"                    Read the events from <readfile>.\n"
" --raw              Print raw output on a regular terminal instead of enabling\n"
"                    ncurses-based ANSI output.\n"
" -s <len>, --snaplen=<len>\n"
"                    Capture the first <len> bytes of each I/O buffer.\n"
"                    By default, the first 80 bytes are captured. Use this\n"
"                    option with caution, it can generate huge trace files.\n"
" -v <view_id>, --view=<view_id>\n"
"                    Run the view with the given ID when csysdig starts.\n"
"                    View IDs can be found in the view documentation pages in\n"
"                    csysdig. Combine  this option with a command line filter for\n"
"                    complete output customization.\n"
" --version          Print version number.\n"
" -X, --print-hex-ascii\n"
"                    When emitting JSON, print data buffers in hex and ASCII.\n"
"\n"
"How to use csysdig:\n"
"1. you can either see real time data, or analyze a trace file by using the -r\n"
"   command line flag.\n"
"2. you can switch to a different view by using the F2 key.\n"
"3. You can drill down into a selection by typing enter.\n"
"   You can navigate back by typing backspace.\n"
"4. you can observe reads and writes (F5) or see sysdig events (F6) for any\n"
"   selection.\n"
"\nAdditional help can be obtained by clicking F1 while the program is running,\n"
"and in the man page.\n\n"
    );
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

static void print_views(chisel_view_manager* view_manager)
{
	Json::FastWriter writer;
	Json::Value root;

	std::vector<chisel_view_info>* vlist = view_manager->get_views();

	for(auto it = vlist->begin(); it != vlist->end(); ++it)
	{
		Json::Value jv;
		chisel_view_info& vinfo = *it;

		jv["id"] = vinfo.m_id;
		jv["name"] = vinfo.m_name;
		jv["description"] = vinfo.m_description;
		jv["isRoot"] = vinfo.m_is_root;
		jv["drilldownTarget"] = vinfo.m_drilldown_target;
		jv["filter"] = vinfo.m_filter;
		jv["canDrillDown"] = (vinfo.m_type == chisel_view_info::T_TABLE);

		for(auto it = vinfo.m_applies_to.begin(); it != vinfo.m_applies_to.end(); ++it)
		{
			jv["appliesTo"].append(*it);
		}
		for(auto it = vinfo.m_tags.begin(); it != vinfo.m_tags.end(); ++it)
		{
			jv["tags"].append(*it);
		}
		for(auto it = vinfo.m_tips.begin(); it != vinfo.m_tips.end(); ++it)
		{
			jv["tips"].append(*it);
		}

		root.append(jv);
	}

	std::string output = writer.write(root);
	printf("%s", output.substr(0, output.size() - 1).c_str());
}
#endif

captureinfo do_inspect(sinsp* inspector,
					   uint64_t cnt,
					   sinsp_cursesui* ui,
					   const chisel_table::output_type& output_type,
                       std::shared_ptr<sinsp_syslog_decoder> syslog_decoder)
{
	captureinfo retval;
	int32_t res;
	sinsp_evt* ev;

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
			break;
		}

        syslog_decoder->reset();
		res = inspector->next(&ev);
        if (ev)
        {
            const uint16_t etype = ev->get_scap_evt()->type;
            if (etype == PPME_SYSCALL_WRITE_X || etype == PPME_SYSCALL_WRITEV_X ||
                etype == PPME_SYSCALL_PWRITE_X || etype == PPME_SYSCALL_PWRITEV_X ||
                etype == PPME_SOCKET_SEND_X || etype == PPME_SOCKET_SENDTO_X ||
                etype == PPME_SOCKET_SENDMSG_X || etype == PPME_SOCKET_SENDMMSG_X)
            {
                syslog_decoder->parse(ev);
            }
        }

		if(res == SCAP_TIMEOUT || res == SCAP_FILTERED_EVENT)
		{
			continue;
		}
		else if(res != SCAP_EOF && res != SCAP_SUCCESS)
		{
			//
			// Event read error.
			// Notify the chisels that we're exiting, and then die with an error.
			//
			if(inspector->is_live())
			{
				throw sinsp_exception(inspector->getlasterr());
			}
			else
			{
				//
				// scap file truncated.
				//
				// We fail gracefully:
				// - all the expected output (except truncated
				//   events) will be on stdout
				// - the return code will be set as success
				// - the inspector error will be on stderr
				//
				ui->set_truncated_input(true);
				if(output_type != chisel_table::OT_CURSES)
				{
					// If we are in the TUI, we don't write anything
					// to stderr: the curses interface will display
					// the trucanted status.
					std::cerr << inspector->getlasterr() << std::endl;
				}
				res = SCAP_EOF;
			}
		}

		if(ui->process_event(ev, res) == true)
		{
			return retval;
		}

		retval.m_nevts++;
	}
	inspector->stop_capture();
	return retval;
}

std::string g_version_string = SYSDIG_VERSION;

//
// CLI11-based argument parser for csysdig
//
csysdig_options parse_args_cli11_csysdig(int argc, char **argv)
{
	csysdig_options opts;

	CLI::App app{"csysdig - the ncurses user interface for sysdig\n"
	             "csysdig version " SYSDIG_VERSION};

	// Disable help flag so we can handle it ourselves for backwards compatibility
	app.set_help_flag("");
	app.allow_extras();  // Allow extra arguments for filter

	// Common options
	app.add_flag("-h,--help", opts.help, "Print this help message");
	app.add_flag("--version", opts.version, "Print version number");
	app.add_flag("-E,--exclude-users", opts.exclude_users, "Don't create user/group tables");
	app.add_flag("-R,--resolve-ports", opts.resolve_ports, "Resolve port numbers to names");
	app.add_flag("-l,--list", opts.list_fields, "List all fields that can be used in views");
	app.add_flag("--list-views", opts.list_views, "List available views");

	// Display format options
	app.add_flag("-A,--print-ascii", opts.print_ascii,
	             "When emitting JSON, print only text portion of data buffers");
	app.add_flag("-X,--print-hex-ascii", opts.print_hex_ascii,
	             "When emitting JSON, print data buffers in hex and ASCII");

	app.add_flag("-j,--json", opts.json, "Enable JSON output");
	app.add_flag("--raw", opts.raw, "Print raw output instead of ncurses");
	app.add_flag("--interactive", opts.interactive, "Enable interactive mode");

	auto print_opt = app.add_option("-p,--print", "Print format (c/container for container-friendly format)");
	print_opt->each([&opts](const std::string& val) {
		if(val == "c" || val == "container") {
			opts.print_containers = true;
		}
	});

	// Capture options
	app.add_option("-B,--bpf", opts.bpf_probe,
	              "Enable live capture using BPF probe")
	   ->expected(0, 1)
	   ->type_name("PROBE");

#ifdef HAS_MODERN_BPF
	app.add_flag("--modern-bpf", opts.modern_bpf,
	            "Enable live capture using modern BPF probe");
	app.add_option("--cpus-for-each-buffer", opts.cpus_for_each_buffer,
	              "CPUs per syscall buffer (modern BPF only)")
	   ->type_name("NUM");
#endif

	app.add_flag("--page-faults", opts.page_faults, "Capture user/kernel page faults");
	app.add_flag("--large-environment", opts.large_environment,
	            "Support environments larger than 4KiB");

	// I/O options
	app.add_option("-r,--read,--readfile", opts.read_files, "Read events from file")
	   ->type_name("FILE")
	   ->check(CLI::ExistingFile);

	app.add_option("-s,--snaplen", opts.snaplen, "Capture first <len> bytes of I/O buffers")
	   ->type_name("LEN");

	app.add_option("-n,--numevents", opts.num_events, "Stop capturing after <num> events")
	   ->type_name("NUM");

	// UI options
	app.add_option("-d,--delay", opts.refresh_interval_ms,
	              "Set delay between updates in milliseconds")
	   ->type_name("MS")
	   ->check(CLI::Range(100, 3600000));  // 100ms to 1 hour

	app.add_option("-v,--view", opts.view_id,
	              "Run the view with the given ID when csysdig starts")
	   ->type_name("VIEW_ID");

	app.add_option("--logfile", opts.logfile, "Print program logs into the given file")
	   ->type_name("FILE");

	app.add_flag("--force-term-compat", opts.force_term_compat,
	            "Try to configure simple terminal settings for better compatibility");

	app.add_option("--from", opts.json_first_row, "First row for JSON output")
	   ->type_name("ROW");

	app.add_option("--to", opts.json_last_row, "Last row for JSON output")
	   ->type_name("ROW");

	app.add_option("--sortingcol", opts.sorting_col, "Sorting column number")
	   ->type_name("COL");

	try {
		app.parse(argc, argv);

		// Collect remaining arguments as filter
		opts.filter_args = app.remaining();

	} catch(const CLI::ParseError &e) {
		throw sinsp_exception(e.what());
	}

	return opts;
}

sysdig_init_res csysdig_init(int argc, char **argv)
{
	sysdig_init_res res;
	sinsp* inspector = NULL;
	std::vector<std::string> infiles;
	uint64_t cnt = -1;
	uint32_t snaplen = 0;
	captureinfo cinfo;
	std::string errorstr;
	std::string filter;
	std::string display_view;
	bool print_containers = false;
	uint64_t refresh_interval_ns = 2000000000;
	bool list_flds = false;
	bool is_interactive = false;
	int32_t json_first_row = 0;
	int32_t json_last_row = 0;
	int32_t sorting_col = -1;
	bool list_views = false;
    std::shared_ptr<sinsp_syslog_decoder> syslog_decoder = std::make_shared<sinsp_syslog_decoder>();

#ifndef _WIN32
	chisel_table::output_type output_type = chisel_table::OT_CURSES;
#else
	chisel_table::output_type output_type = chisel_table::OT_JSON;
#endif
	bool terminal_with_mouse = false;
	bool force_term_compat = false;
	sinsp_evt::param_fmt event_buffer_format = sinsp_evt::PF_NORMAL;
	plugin_utils plugins;
	sinsp_opener opener;
	std::shared_ptr<sinsp_filter_check_list> filter_list;

	//
	// Parse the arguments
	//
	try
	{
		auto normalized_args = normalize_csysdig_argv(argc, argv);
		auto normalized_argv = argv_ptrs_csysdig(normalized_args);
		auto opts = parse_args_cli11_csysdig((int)normalized_argv.size(), normalized_argv.data());

		inspector = new sinsp();

#ifdef HAS_CHISELS
		add_chisel_dirs(inspector);
#endif
		plugins.add_directory(SYSDIG_PLUGINS_DIR);
		plugins.read_plugins_from_dirs(inspector);

		// Load container plugin (if available)
		plugins.load_container_plugin_if_available(inspector);

		if(count_enabled_formats(opts) > 1)
		{
			fprintf(stderr, "you cannot specify more than one output format\n");
			delete inspector;
			return sysdig_init_res(EXIT_FAILURE);
		}

		if(opts.help)
		{
			usage();
			delete inspector;
			return sysdig_init_res(EXIT_SUCCESS);
		}

		if(opts.version)
		{
			printf("sysdig version %s\n", SYSDIG_VERSION);
			delete inspector;
			return sysdig_init_res(EXIT_SUCCESS);
		}

		if(opts.print_ascii)
		{
			event_buffer_format = sinsp_evt::PF_EOLS_COMPACT;
		}
		else if(opts.print_hex_ascii)
		{
			event_buffer_format = sinsp_evt::PF_HEXASCII;
		}

		if(!opts.bpf_probe.empty() || std::find(normalized_args.begin(), normalized_args.end(), "-B") != normalized_args.end())
		{
			opener.bpf.enabled = true;
			opener.bpf.probe = opts.bpf_probe;
		}

		if(opts.refresh_interval_ms != 2000)
		{
			refresh_interval_ns = opts.refresh_interval_ms * 1000000;
			if(refresh_interval_ns < 100000000)
			{
				throw sinsp_exception("Period must be bigger then 100ms");
			}
		}

		if(opts.exclude_users)
		{
			inspector->set_import_users(false);
		}

		if(opts.json)
		{
			output_type = chisel_table::OT_JSON;
		}

		list_flds = opts.list_fields;

		if(opts.num_events != std::numeric_limits<uint64_t>::max())
		{
			if(opts.num_events == 0)
			{
				throw sinsp_exception("invalid event count 0");
			}
			cnt = opts.num_events;
		}

		print_containers = opts.print_containers;

		if(opts.resolve_ports)
		{
			inspector->set_hostname_and_port_resolution_mode(true);
		}

		infiles = opts.read_files;
		snaplen = (uint32_t)opts.snaplen;
		display_view = opts.view_id;

		if(opts.interactive)
		{
			is_interactive = true;
			output_type = chisel_table::OT_JSON;
		}

		if(opts.large_environment)
		{
			inspector->set_large_envs(true);
		}

#ifdef HAS_MODERN_BPF
		if(opts.cpus_for_each_buffer != 0)
		{
			opener.bpf.cpus_for_each_syscall_buffer = (uint16_t)opts.cpus_for_each_buffer;
		}
		if(opts.modern_bpf)
		{
			opener.bpf.enabled = true;
			opener.bpf.modern = true;
		}
#endif

		if(!opts.logfile.empty())
		{
			inspector->set_log_file(opts.logfile.c_str());
		}

		if(opts.raw)
		{
			output_type = chisel_table::OT_RAW;
		}

		force_term_compat = opts.force_term_compat;
		json_first_row = opts.json_first_row;
		json_last_row = opts.json_last_row;
		sorting_col = opts.sorting_col;
		list_views = opts.list_views;

		if(opts.page_faults)
		{
			opener.options.page_faults = true;
		}

		if(!opts.filter_args.empty())
		{
			for(size_t j = 0; j < opts.filter_args.size(); j++)
			{
				filter += opts.filter_args[j];
				if(j + 1 < opts.filter_args.size())
				{
					filter += " ";
				}
			}
		}

		//
		// If -l was specified, print the fields and exit
		//
		if(list_flds)
		{
			// todo(jasondellaluce): support source selection, verbosity, markdown
			print_supported_fields(inspector, plugins, "", true, false);
			res.m_res = EXIT_SUCCESS;
			goto exit;
		}

		// TODO(therealbobo): add plugins filterchecks
		filter_list = std::make_shared<sinsp_filter_check_list>();
        filter_list->add_filter_check(std::make_unique<sinsp_filter_check_syslog>(syslog_decoder));
		plugins.init_loaded_plugins(inspector, filter_list.get());

		for (auto plugin : inspector->m_plugin_manager->plugins())
		{
			if (plugin->caps() & CAP_EXTRACTION)
			{
				// todo(therealbobo): manage field name conflicts
				filter_list->add_filter_check(sinsp_plugin::new_filtercheck(plugin));
			}
		}

		if(!opener.bpf.enabled)
		{
			const char *probe = getenv("SYSDIG_BPF_PROBE");
			if(probe)
			{
				opener.bpf.enabled = true;
				opener.bpf.probe = probe;
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

		if(json_last_row < json_first_row)
		{
			fprintf(stderr, "'to' argument cannot be smaller than the 'from' one.\n");
			res.m_res = EXIT_FAILURE;
			goto exit;
		}

		//
		// Initialize ncurses
		//
#ifndef NOCURSESUI
		if(output_type == chisel_table::OT_CURSES)
		{
			char* eterm = getenv("TERM");

			std::vector<std::string> terminal_types =
			{
				MOUSE_CAPABLE_TERM,
				eterm,
				"xterm",
				"xterm-color"
			};

			SCREEN* screen = NULL;

			if(force_term_compat)
			{
				terminal_types.clear();
				terminal_types.push_back(MOUSE_CAPABLE_TERM_COMPAT);
			}

			//
			// Try some of the most capable terminals, reverting to basic
			// xterm if none works
			//
			for(const auto& term : terminal_types)
			{
				screen = newterm(term.c_str(), stdout, stdin);
				if(screen != NULL)
				{
					break;
				}
			}

			if(screen == NULL)
			{
				fprintf(stderr, "Error: Failed to initialize terminal.\n");
				exit(1);
			}

			set_term(screen);

			(void) nonl();         // tell curses not to do NL->CR/NL on output
			intrflush(stdscr, false);
			keypad(stdscr, true);
			curs_set(0);
			if(has_colors())
			{
			  start_color();
			}
			use_default_colors();
			mousemask(ALL_MOUSE_EVENTS | REPORT_MOUSE_POSITION, NULL);
			noecho();

			timeout(0);

			// If this is uncommented, it's possible to natively handle stuff like CTRL+c
			//raw();
		}
#endif

		//
		// Create the list of views
		//
		chisel_view_manager view_manager;

		//
		// Scan the chisel list to load the Lua views, and add them to the list
		//
		std::vector<chisel_desc> chlist;
		sinsp_chisel::get_chisel_list(&chlist);

		for(auto it : chlist)
		{
			if(it.m_viewinfo.m_valid)
			{
				if(print_containers)
				{
					it.m_viewinfo.apply_tag("containers");
				}
				else
				{
					it.m_viewinfo.apply_tag("default");
				}

				if(it.m_viewinfo.m_tags.size() != 0)
				{
					if(it.m_viewinfo.m_tags[0] == "Containers")
					{
						continue;
					}
				}

				if(output_type != chisel_table::OT_JSON)
				{
					if(std::find(it.m_viewinfo.m_tags.begin(),
						it.m_viewinfo.m_tags.end(),
						"nocsysdig") != it.m_viewinfo.m_tags.end())
					{
						continue;
					}
				}

				view_manager.add(&it.m_viewinfo);
			}
		}

		//
		// Set the initial display view
		//
		view_manager.set_selected_view(display_view);

		if(list_views)
		{
			print_views(&view_manager);
			goto exit;
		}

		//
		// Go through the input sources and apply the processing to all of them
		//
		for(uint32_t j = 0; j < infiles.size() || infiles.size() == 0; j++)
		{
			//
			// Initialize the UI
			//
			sinsp_cursesui ui(inspector,
				filter_list,
				&opener,
				(filter.size() != 0)? filter : "",
				refresh_interval_ns,
				print_containers,
				output_type,
				terminal_with_mouse,
				json_first_row,
				json_last_row,
				sorting_col,
				event_buffer_format);

			ui.configure(&view_manager);

			if(display_view == "dig" || display_view == "echo")
			{
				ui.start(false, true);
			}
			else
			{
				ui.start(false, false);
			}

			if(is_interactive)
			{
				printf("ready\n");

				//
				// In interactive mode, make sure stderr is flushed at every printf
				//
				setbuf(stderr, NULL);

				//
				// Set the UI in interactive mode and start listening to user
				// input.
				//
				ui.set_interactive(true);
			}

			//
			// Launch the capture
			//
			if(infiles.size() != 0)
			{
				//
				// We have a file to open
				//
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
				opener.open(inspector);
			}

			//
			// If required, set the snaplen
			//
			if(snaplen != 0)
			{
				inspector->set_snaplen(snaplen);
			}

			if(output_type == chisel_table::OT_JSON)
			{
				printf("{\"slices\": [\n");
				if(display_view != "dig" && display_view != "echo")
				{
					printf("{\"progress\": 0},\n");
				}
			}

			//
			// Start the capture loop
			//
            cinfo = do_inspect(inspector, cnt, &ui, output_type, syslog_decoder);

			if(output_type == chisel_table::OT_JSON)
			{
				printf("]}\n");
				//printf("%c", EOF);
			}

			//
			// Done. Close the inspector.
			//
			inspector->close();
		}
	}
	catch(const chisel_capture_interrupt_exception&)
	{
	}
	catch(const scap_open_exception& e)
	{
		errorstr = e.what();
		res.m_res = e.scap_rc();
	}
	catch(const std::exception& e)
	{
		errorstr = e.what();
		res.m_res = EXIT_FAILURE;
	}
	catch(...)
	{
		errorstr = "uncaught exception";
		res.m_res = EXIT_FAILURE;
	}

exit:
	if(inspector)
	{
		delete inspector;
	}

	//
	// Restore the original screen
	//
#ifndef NOCURSESUI
	if(output_type == chisel_table::OT_CURSES)
	{
		endwin();
	}
#endif

	if(errorstr != "")
	{
		std::cerr << errorstr << std::endl;
	}

	return res;
}

//
// MAIN
//
int main(int argc, char **argv)
{
	sysdig_init_res res;

	//
	// Run csysdig
	//
	res = csysdig_init(argc, argv);

#ifdef _WIN32
	_CrtDumpMemoryLeaks();
#endif

	return res.m_res;
}
