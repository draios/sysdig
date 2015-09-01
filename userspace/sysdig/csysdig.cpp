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
#endif

#include "cursescomponents.h"
#include "cursestable.h"
#include "cursesui.h"

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
" -l, --list         List all the fields that can be used in views.\n"
" --logfile=<file>\n"
"                    Print program logs into the given file.\n"
" -N\n"
"                    Don't convert addresses (i.e., host addresses, port numbers,\n"
"                     etc.) to names.\n"
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
"3. You can to drill down into a selection by typing enter.\n"
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

	static struct option long_options[] =
	{
		{"delay", required_argument, 0, 'd' },
		{"exclude-users", no_argument, 0, 'E' },
		{"help", no_argument, 0, 'h' },
		{"list", optional_argument, 0, 'l' },
		{"numevents", required_argument, 0, 'n' },
		{"print", required_argument, 0, 'p' },
		{"readfile", required_argument, 0, 'r' },
		{"raw", no_argument, 0, 0 },
		{"snaplen", required_argument, 0, 's' },
		{"logfile", required_argument, 0, 0 },
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
			"d:EhlNn:p:r:s:v:", long_options, &long_index)) != -1)
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
			case 'l':
				list_flds = true;
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
				break;
			case 's':
				snaplen = atoi(optarg);
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
			list_fields(false);

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
			(void) initscr();      // initialize the curses library
			(void) nonl();         // tell curses not to do NL->CR/NL on output
			intrflush(stdscr, false);
			keypad(stdscr, true);
			curs_set(0);
			if (has_colors())
			{
			  start_color();
			}
			use_default_colors();
			mousemask(ALL_MOUSE_EVENTS, NULL);
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
				m_raw_output);

			ui.configure(&view_manager);
			ui.start(false, false);

			//
			// Launch the capture
			//
			bool open_success = true;

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
				try
				{
					inspector->open("");
				}
				catch(sinsp_exception e)
				{
					open_success = false;
				}
#else
				//
				// Starting live capture
				// If this fails on Windows and OSX, don't try with any driver
				//
				inspector->open("");
#endif

				//
				// Starting the live capture failed, try to load the driver with
				// modprobe.
				//
				if(!open_success)
				{
					open_success = true;

					if(system("modprobe sysdig-probe > /dev/null 2> /dev/null"))
					{
						fprintf(stderr, "Unable to load the driver\n");
					}

					inspector->open("");
				}

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
	catch(sinsp_exception& e)
	{
		errorstr = e.what();
		res.m_res = EXIT_FAILURE;
	}
	catch(...)
	{
		errorstr = "uncatched exception";
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

	res = csysdig_init(argc, argv);

#ifdef _WIN32
	_CrtDumpMemoryLeaks();
#endif

	return res.m_res;
}
