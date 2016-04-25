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

#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <iostream>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <assert.h>
#include <algorithm>

#include <sinsp.h>
#include "chisel.h"
#include "sysdig.h"
#include "table.h"
#include "utils.h"

#ifdef _WIN32
#include "win32/getopt.h"
#include <io.h>
#else
#include <unistd.h>
#include <getopt.h>
#include <term.h>
#endif

#include "cursescomponents.h"
#include "cursestable.h"
#include "cursesui.h"

#define MOUSE_CAPABLE_TERM "xterm-1003"

static bool g_terminate = false;
static void usage();

//
// Helper functions
//
static void signal_callback(int signal)
{
	g_terminate = true;
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
" -h, --help         Print this page\n"
" -k <url>, --k8s-api=<url>\n"
"                    Enable Kubernetes support by connecting to the API server\n"
"                    specified as argument. E.g. \"http://admin:password@127.0.0.1:8080\".\n"
"                    The API server can also be specified via the environment variable\n"
"                    SYSDIG_K8S_API.\n"
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
" -l, --list         List all the fields that can be used in views.\n"
" --logfile=<file>\n"
"                    Print program logs into the given file.\n"
" -N\n"
"                    Don't convert port numbers to names.\n"
" -n <num>, --numevents=<num>\n"
"                    Stop capturing after <num> events\n"
" -pc, -pcontainer\n"
"                    Instruct csysdig to use a container-friendly format in its\n"
"                    views.\n"
"                    This will cause several of the views to contain additional\n"
"                    container-related columns.\n"
" -r <readfile>, --read=<readfile>\n"
"                    Read the events from <readfile>.\n"
" --raw              Print raw output on a regular terminal instead of enabling\n"
"                    ncurses-based ANSI output.\n"
" -s <len>, --snaplen=<len>\n"
"                    Capture the first <len> bytes of each I/O buffer.\n"
"                    By default, the first 80 bytes are captured. Use this\n"
"                    option with caution, it can generate huge trace files.\n"
" -T, --force-tracers-capture\n"
"                    Tell the driver to make sure full buffers are captured from\n"
"                    /dev/null, to make sure that tracers are completely\n"
"                    captured. Note that sysdig will enable extended /dev/null\n"
"                    capture by itself after detecting that tracers are written\n"
"                    there, but that could result in the truncation of some\n"
"                    tracers at the beginning of the capture. This option allows\n"
"                    preventing that.\n"
" -v <view_id>, --view=<view_id>\n"
"                    Run the view with the given ID when csysdig starts.\n"
"                    View IDs can be found in the view documentation pages in\n"
"                    csysdig. Combine  this option with a command line filter for\n"
"                    complete output customization.\n"
" --version          Print version number.\n"
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
	inspector->add_chisel_dir(SYSDIG_INSTALLATION_DIR CHISELS_INSTALLATION_DIR, false);

	//
	// Add the directories configured in the SYSDIG_CHISEL_DIR environment variable
	//
	char* s_user_cdirs = getenv("SYSDIG_CHISEL_DIR");

	if(s_user_cdirs != NULL)
	{
		vector<string> user_cdirs = sinsp_split(s_user_cdirs, ';');

		for(uint32_t j = 0; j < user_cdirs.size(); j++)
		{
			inspector->add_chisel_dir(user_cdirs[j], true);
		}
	}
}
#endif

captureinfo do_inspect(sinsp* inspector,
					   uint64_t cnt,
					   sinsp_cursesui* ui)
{
	captureinfo retval;
	int32_t res;
	sinsp_evt* ev;

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

		res = inspector->next(&ev);

		if(res == SCAP_TIMEOUT)
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
				ui->set_truncated_input(true);
				res = SCAP_EOF;
				continue;
			}
		}

		if(ui->process_event(ev, res) == true)
		{
			return retval;
		}

		retval.m_nevts++;
	}

	return retval;
}

string g_version_string = SYSDIG_VERSION;

sysdig_init_res csysdig_init(int argc, char **argv)
{
	sysdig_init_res res;
	sinsp* inspector = NULL;
	vector<string> infiles;
	int op;
	uint64_t cnt = -1;
	uint32_t snaplen = 0;
	int long_index = 0;
	int32_t n_filterargs = 0;
	captureinfo cinfo;
	string errorstr;
	string display_view;
	bool print_containers = false;
	uint64_t refresh_interval_ns = 2000000000;
	bool list_flds = false;
	bool m_raw_output = false;
	string* k8s_api = 0;
	string* k8s_api_cert = 0;
	string* mesos_api = 0;
	bool xt1002_available = false;
	bool force_tracers_capture = false;

	static struct option long_options[] =
	{
		{"delay", required_argument, 0, 'd' },
		{"exclude-users", no_argument, 0, 'E' },
		{"help", no_argument, 0, 'h' },
		{"k8s-api", required_argument, 0, 'k'},
		{"k8s-api-cert", required_argument, 0, 'K' },
		{"list", optional_argument, 0, 'l' },
		{"mesos-api", required_argument, 0, 'm'},
		{"numevents", required_argument, 0, 'n' },
		{"print", required_argument, 0, 'p' },
		{"readfile", required_argument, 0, 'r' },
		{"raw", no_argument, 0, 0 },
		{"snaplen", required_argument, 0, 's' },
		{"logfile", required_argument, 0, 0 },
		{"force-tracers-capture", required_argument, 0, 'T'},
		{"view", required_argument, 0, 'v' },
		{"version", no_argument, 0, 0 },
		{0, 0, 0, 0}
	};

	//
	// Parse the arguments
	//
	try
	{
		inspector = new sinsp();

#ifdef HAS_CHISELS
		add_chisel_dirs(inspector);
#endif

		//
		// Parse the args
		//
		while((op = getopt_long(argc, argv,
			"d:Ehk:K:lm:Nn:p:r:s:Tv:", long_options, &long_index)) != -1)
		{
			switch(op)
			{
			case '?':
				//
				// Command line error 
				//
				throw sinsp_exception("command line error");
				break;
			case 'd':
				try
				{
					refresh_interval_ns = sinsp_numparser::parseu64(optarg) * 1000000;
				}
				catch(...)
				{
					throw sinsp_exception("can't parse the -d argument, make sure it's a number");
				}

				if(refresh_interval_ns < 100000000)
				{
					throw sinsp_exception("Period must be bigger then 100ms");
				}

				break;
			case 'E':
				inspector->set_import_users(false);
				break;
			case 'h':
				usage();
				delete inspector;
				return sysdig_init_res(EXIT_SUCCESS);
			case 'k':
				k8s_api = new string(optarg);
				break;
			case 'K':
				k8s_api_cert = new string(optarg);
				break;
			case 'l':
				list_flds = true;
				break;
			case 'm':
				mesos_api = new string(optarg);
				break;
			case 'N':
				inspector->set_hostname_and_port_resolution_mode(false);
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
					throw sinsp_exception(string("invalid event count ") + optarg);
					res.m_res = EXIT_FAILURE;
					goto exit;
				}
				break;
			case 'p':
				if(string(optarg) == "c" || string(optarg) == "container")
				{
					inspector->set_print_container_data(true);
					print_containers = true;
				}

				break;
			case 'r':
				infiles.push_back(optarg);
				k8s_api = new string();
				mesos_api = new string();
				break;
			case 's':
				snaplen = atoi(optarg);
				break;
			case 'T':
				force_tracers_capture = true;
				break;
			case 'v':
				display_view = optarg;
				break;
			case 0:
				{
					if(long_options[long_index].flag != 0)
					{
						break;
					}

					string optname = string(long_options[long_index].name);
					if(optname == "version")
					{
						printf("sysdig version %s\n", SYSDIG_VERSION);
						delete inspector;
						return sysdig_init_res(EXIT_SUCCESS);
					}
					else if(optname == "logfile")
					{
						inspector->set_log_file(optarg);
					}
					else if(optname == "raw")
					{
						m_raw_output = true;
					}
				}
				break;
			default:
				break;
			}
		}

		string filter;

		//
		// If -l was specified, print the fields and exit
		//
		if(list_flds)
		{
			list_fields(false, false);

			res.m_res = EXIT_SUCCESS;
			goto exit;
		}

		//
		// the filter is at the end of the command line
		//
		if(optind + n_filterargs < argc)
		{
#ifdef HAS_FILTERING
			for(int32_t j = optind + n_filterargs; j < argc; j++)
			{
				filter += argv[j];
				if(j < argc)
				{
					filter += " ";
				}
			}
#else
			fprintf(stderr, "filtering not compiled.\n");
			res.m_res = EXIT_FAILURE;
			goto exit;
#endif
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

		//
		// Initialize ncurses
		//
#ifndef NOCURSESUI
		if(!m_raw_output)
		{
			//
			// Check if xterm-1002 is available
			//
			xt1002_available = (tgetent(NULL, MOUSE_CAPABLE_TERM) != 0);

			if(xt1002_available)
			{
				//
				// Enable fine-grained mouse activity capture by setting xterm-1002
				//
				setenv("TERM", MOUSE_CAPABLE_TERM, 1);
			}

			(void) initscr();      // initialize the curses library
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
		sinsp_view_manager view_manager;

		//
		// Scan the chisel list to load the Lua views, and add them to the list
		//
		vector<chisel_desc> chlist;
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

				view_manager.add(&it.m_viewinfo);
			}
		}

		//
		// Set the initial disply view
		//
		view_manager.set_selected_view(display_view);

		//
		// Go through the input sources and apply the processing to all of them
		//
		for(uint32_t j = 0; j < infiles.size() || infiles.size() == 0; j++)
		{
			//
			// Initialize the UI
			//
			sinsp_cursesui ui(inspector, 
				(infiles.size() != 0)? infiles[0] : "",
				(filter.size() != 0)? filter : "",
				refresh_interval_ns,
				print_containers,
				m_raw_output,
				xt1002_available);

			ui.configure(&view_manager);
			ui.start(false, false);

			//
			// Launch the capture
			//
			if(infiles.size() != 0)
			{
				//
				// We have a file to open
				//
				inspector->open(infiles[j]);
			}
			else
			{
				if(j > 0)
				{
					break;
				}

				//
				// No file to open, this is a live capture
				//
#if defined(HAS_CAPTURE)
				bool open_success = true;
				
				try
				{
					inspector->open("");
				}
				catch(sinsp_exception e)
				{
					open_success = false;
				}

				//
				// Starting the live capture failed, try to load the driver with
				// modprobe.
				//
				if(!open_success)
				{
					open_success = true;

					if(system("modprobe " PROBE_NAME " > /dev/null 2> /dev/null"))
					{
						fprintf(stderr, "Unable to load the driver\n");
					}

					inspector->open("");
				}
#else
				//
				// Starting live capture
				// If this fails on Windows and OSX, don't try with any driver
				//
				inspector->open("");
#endif

				//
				// Enable gathering the CPU from the kernel module
				//
				inspector->set_get_procs_cpu_from_driver(true);
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

			//
			// run k8s, if required
			//
			if(k8s_api)
			{
				if(!k8s_api_cert)
				{
					if(char* k8s_cert_env = getenv("SYSDIG_K8S_API_CERT"))
					{
						k8s_api_cert = new string(k8s_cert_env);
					}
				}
				inspector->init_k8s_client(k8s_api, k8s_api_cert);
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
							k8s_api_cert = new string(k8s_cert_env);
						}
					}
					k8s_api = new string(k8s_api_env);
					inspector->init_k8s_client(k8s_api, k8s_api_cert);
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
				inspector->init_mesos_client(mesos_api);
			}
			else if(char* mesos_api_env = getenv("SYSDIG_MESOS_API"))
			{
				if(mesos_api_env != NULL)
				{
					mesos_api = new string(mesos_api_env);
					inspector->init_mesos_client(mesos_api);
				}
			}
			delete mesos_api;
			mesos_api = 0;

			//
			// Start the capture loop
			//
			cinfo = do_inspect(inspector,
				cnt,
				&ui);

			//
			// Done. Close the capture.
			//
			inspector->close();
		}
	}
	catch(sinsp_capture_interrupt_exception&)
	{
	}
	catch(std::exception& e)
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
	if(!m_raw_output)
	{
		endwin();
	}
#endif

	if(errorstr != "")
	{
		cerr << errorstr << endl;
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
