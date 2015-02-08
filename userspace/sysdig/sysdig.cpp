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
#include "sysdig.h"
#include "chisel.h"
#include "table.h"

#ifdef _WIN32
#include "win32/getopt.h"
#include <io.h>
#else
#include <unistd.h>
#include <getopt.h>
#endif

#include "cursestable.h"
#include "cursesui.h"

static bool g_terminate = false;
#ifdef HAS_CHISELS
vector<sinsp_chisel*> g_chisels;
#endif

// Sysdig 0.1.85 had log-rotation options (-C,-G,-W), but they were problematic,
// so I'm disabling them until they can be fixed
#define DISABLE_CGW


static void usage();

//
// Helper functions
//
static void signal_callback(int signal)
{
	g_terminate = true;
}

void replace_in_place(string& str, string substr_to_replace, string new_substr)
{
	size_t index = 0;
	uint32_t nsize = (uint32_t)substr_to_replace.size();

	while (true)
	{
		 index = str.find(substr_to_replace, index);
		 if (index == string::npos) break;

		 str.replace(index, nsize, new_substr);

		 index += nsize;
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
#ifdef HAS_CHISELS
" -c <chiselname> <chiselargs>, --chisel  <chiselname> <chiselargs>\n"
"                    run the specified chisel. If the chisel require arguments,\n"
"                    they must be specified in the command line after the name.\n"
" -cl, --list-chisels\n"
"                    lists the available chisels. Looks for chisels in\n"
"                    ./chisels, ~/.chisels and /usr/share/sysdig/chisels.\n"
#endif
#ifndef DISABLE_CGW
" -C <file_size>, --file-size=<file_size>\n"
"                    Before writing an event, check whether the file is\n"
"                    currently larger than file_size and, if so, close the\n"
"                    current file and open a new one. Savefiles will have the\n"
"                    name specified with the -w flag, with a number after it,\n"
"                    starting at 0 and continuing upward. The units of file_size\n"
"                    are millions of bytes (10^6, not 2^20). Use the -W flag to\n"
"                    determine how many files will be saved to disk.\n"
#endif
" -d, --displayflt   Make the given filter a display one\n"
"                    Setting this option causes the events to be filtered\n"
"                    after being parsed by the state system. Events are\n"
"                    normally filtered before being analyzed, which is more\n"
"                    efficient, but can cause state (e.g. FD names) to be lost.\n"
" -D, --debug        Capture events about sysdig itself\n"
" -E, --exclude-users\n"
"                    Don't create the user/group tables by querying the OS when\n"
"                    sysdig starts. This also means that no user or group info\n"
"                    will be written to the tracefile by the -w flag.\n"
"                    The user/group tables are necessary to use filter fields\n"
"                    like user.name or group.name. However, creating them can\n"
"                    increase sysdig's startup time. Moreover, they contain\n"
"                    information that could be privacy sensitive.\n"
" -F, --fatfile	     Enable fatfile mode\n"
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
#ifndef DISABLE_CGW
" -G <num_seconds>, --seconds=<num_seconds>\n"
"                    Rotates the dump file specified with the -w option every\n"
"                    num_seconds seconds. Savefiles will have the name specified\n"
"                    by -w which should include a time format as defined by strftime(3).\n"
"                    If no time format is specified, each new file will overwrite the\n"
"                    previous.\n"
"\n"
"                    If used in conjunction with the -C option, filenames will take\n"
"                    the form of `file<count>'.\n"
#endif
" -h, --help         Print this page\n"
#ifdef HAS_CHISELS
" -i <chiselname>, --chisel-info <chiselname>\n"
"                    Get a longer description and the arguments associated with\n"
"                    a chisel found in the -cl option list.\n"
#endif
" -j, --json         Emit output as json, data buffer encoding will depend from the\n"
"                    print format selected.\n"
" -L, --list-events  List the events that the engine supports\n"
" -l, --list         List the fields that can be used for filtering and output\n"
"                    formatting. Use -lv to get additional information for each\n"
"                    field.\n"
" -n <num>, --numevents=<num>\n"
"                    Stop capturing after <num> events\n"
" -P, --progress     Print progress on stderr while processing trace files\n"
" -p <output_format>, --print=<output_format>\n"
"                    Specify the format to be used when printing the events.\n"
"                    With -pc or -pcontainer will use a container-friendly format.\n"
"                    See the examples section below for more info.\n"
" -q, --quiet        Don't print events on the screen\n"
"                    Useful when dumping to disk.\n"
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
#ifndef DISABLE_CGW
" -W <num>, --limit <num>\n"
"                    Used in conjunction with the -C option, this will limit the number\n"
"                    of files created to the specified number, and begin overwriting files\n"
"                    from the beginning, thus creating a 'rotating' buffer. In addition, it\n"
"                    will name the files with enough leading 0s to support the maximum number\n"
"                    of files, allowing them to sort correctly.\n"
"\n"
"                    Used in conjunction with the -G option, this will limit the number\n"
"                    of rotated dump files that get created, exiting with status 0 when\n"
"                    reaching the limit. If used with -C as well, the behavior will result\n"
"                    in cyclical files per timeslice.\n"
#endif
" -x, --print-hex    Print data buffers in hex.\n"
" -X, --print-hex-ascii\n"
"                    Print data buffers in hex and ASCII.\n"
" -z, --compress     Used with -w, enables compression for tracefiles.\n"
"\n"
"Output format:\n\n"
"By default, sysdig prints the information for each captured event on a single\n"
" line with the following format:\n\n"
" %%evt.num %%evt.time %%evt.cpu %%proc.name (%%thread.tid) %%evt.dir %%evt.type %%evt.info\n\n"
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
"%%evt.num %%evt.time %%evt.cpu %%container.name (%%container.id) %%proc.name (%%thread.tid:%%thread.vtid) %%evt.dir %%evt.type %%evt.info\n\n"
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
    );
}

void print_summary_table(sinsp* inspector,
						 vector<summary_table_entry>* summary_table,
						 uint32_t nentries)
{
	sinsp_evttables* einfo = inspector->get_event_info_tables();

	cout << "----------------------\n";
	string tstr = string("Event");
	tstr.resize(16, ' ');
	tstr += "#Calls\n";
	cout << tstr;
	cout << "----------------------\n";

	sort(summary_table->begin(), summary_table->end(),
		summary_table_entry_rsort_comparer());

	for(uint32_t j = 0; j < nentries; j++)
	{
		summary_table_entry* e = &summary_table->at(j);

		if(e->m_ncalls == 0)
		{
			break;
		}

		if(e->m_is_unsupported_syscall)
		{
			tstr = einfo->m_syscall_info_table[e->m_id / 2].name;
			tstr.resize(16, ' ');

			printf("%s%s%" PRIu64 "\n",
				(PPME_IS_ENTER(e->m_id))? "> ": "< ",
				tstr.c_str(),
				e->m_ncalls);
		}
		else
		{
			tstr = einfo->m_event_info[e->m_id].name;
			tstr.resize(16, ' ');

			printf("%s%s%" PRIu64 "\n",
				(PPME_IS_ENTER(e->m_id))? "> ": "< ",
				tstr.c_str(),
				e->m_ncalls);
		}
	}
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
	string args;

	if(nargs != 0)
	{
		if(optind > (int32_t)argc)
		{
			throw sinsp_exception("invalid number of arguments for chisel " + string(optarg) + ", " + to_string((long long int)nargs) + " expected.");
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
					string testflt;

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
							sinsp_filter df(inspector, testflt);
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
				throw sinsp_exception("missing arguments for chisel " + string(optarg));
			}
		}
	}
}

static void free_chisels()
{
#ifdef HAS_CHISELS
	for(vector<sinsp_chisel*>::iterator it = g_chisels.begin();
		it != g_chisels.end(); ++it)
	{
		delete *it;
	}

	g_chisels.clear();
#endif
}

static void chisels_on_capture_start()
{
#ifdef HAS_CHISELS
	for(uint32_t j = 0; j < g_chisels.size(); j++)
	{
		g_chisels[j]->on_capture_start();
	}
#endif
}

static void chisels_on_capture_end()
{
#ifdef HAS_CHISELS
	for(vector<sinsp_chisel*>::iterator it = g_chisels.begin();
		it != g_chisels.end(); ++it)
	{
		(*it)->on_capture_end();
	}
#endif
}

static void chisels_do_timeout(sinsp_evt* ev)
{
#ifdef HAS_CHISELS
	for(vector<sinsp_chisel*>::iterator it = g_chisels.begin();
		it != g_chisels.end(); ++it)
	{
		(*it)->do_timeout(ev);
	}
#endif
}

void handle_end_of_file(bool print_progress, sinsp_evt_formatter* formatter = NULL)
{
	string line;

	// Notify the formatter that we are at the
	// end of the capture in case it needs to
	// write any terminating characters
	if(formatter != NULL && formatter->on_capture_end(&line))
	{
		cout << line << endl;
	}

	//
	// Reached the end of a trace file.
	// If we are reporting prgress, this is 100%
	//
	if(print_progress)
	{
		fprintf(stderr, "100.00\n");
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

//
// Event processing loop
//
captureinfo do_inspect(sinsp* inspector,
					   uint64_t cnt,
					   bool quiet,
					   bool json,
					   bool print_progress,
					   sinsp_filter* display_filter,
					   vector<summary_table_entry>* summary_table,
					   sinsp_evt_formatter* formatter,
					   vector<sinsp_table>* tables)
{
	captureinfo retval;
	int32_t res;
	sinsp_evt* ev;
	uint64_t ts;
	uint64_t deltats = 0;
	uint64_t firstts = 0;
	string line;
	double last_printed_progress_pct = 0;

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
			handle_end_of_file(print_progress, formatter);
			break;
		}

		res = inspector->next(&ev);

		if(res == SCAP_TIMEOUT)
		{
			if(ev != NULL && ev->is_filtered_out())
			{
				//
				// The event has been dropped by the filtering system.
				// Give the chisels a chance to run their timeout logic.
				//
				chisels_do_timeout(ev);
			}

			continue;
		}
		else if(res == SCAP_EOF)
		{
			handle_end_of_file(print_progress, formatter);
			break;
		}
		else if(res != SCAP_SUCCESS)
		{
			//
			// Event read error.
			// Notify the chisels that we're exiting, and then die with an error.
			//
			handle_end_of_file(print_progress, formatter);
			cerr << "res = " << res << endl;
			throw sinsp_exception(inspector->getlasterr().c_str());
		}

		retval.m_nevts++;

		ts = ev->get_ts();
		if(firstts == 0)
		{
			firstts = ts;
		}
		deltats = ts - firstts;

		if(print_progress)
		{
			if(ev->get_num() % 10000 == 0)
			{
				double progress_pct = inspector->get_read_progress();

				if(progress_pct - last_printed_progress_pct > 0.1)
				{
					fprintf(stderr, "%.2lf\n", progress_pct);
					fflush(stderr);
					last_printed_progress_pct = progress_pct;
				}
			}
		}

		//
		// If there are chisels to run, run them
		//
#ifdef HAS_CHISELS
		if(!g_chisels.empty())
		{
			for(vector<sinsp_chisel*>::iterator it = g_chisels.begin(); it != g_chisels.end(); ++it)
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
			if(summary_table != NULL)
			{
				uint16_t etype = ev->get_type();

				if(etype == PPME_GENERIC_E)
				{
					sinsp_evt_param *parinfo = ev->get_param(0);
					uint16_t id = *(int16_t *)parinfo->m_val;
					((*summary_table)[PPM_EVENT_MAX + id * 2]).m_ncalls++;
				}
				else if(etype == PPME_GENERIC_X)
				{
					sinsp_evt_param *parinfo = ev->get_param(0);
					uint16_t id = *(int16_t *)parinfo->m_val;
					((*summary_table)[PPM_EVENT_MAX + id * 2 + 1]).m_ncalls++;
				}
				else
				{
					((*summary_table)[etype]).m_ncalls++;
				}
			}

			//
			// If there are tables to update, update them
			//
			for(auto it = tables->begin(); it != tables->end(); ++it)
			{
				it->process_event(ev);
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

			if(formatter->tostring(ev, &line))
			{
				//
				// Output the line
				//
				if(display_filter)
				{
					if(!display_filter->run(ev))
					{
						continue;
					}
				}

				cout << line;
				if(!json)
				{
					cout << endl;
				}
				else
				{
					cout << flush;
				}
			}
		}
	}

	retval.m_time = deltats;
	return retval;
}

//
// ARGUMENT PARSING AND PROGRAM SETUP
//
sysdig_init_res sysdig_init(int argc, char **argv)
{
	sysdig_init_res res;
	sinsp* inspector = NULL;
	vector<string> infiles;
	string outfile;
	int op;
	uint64_t cnt = -1;
	bool quiet = false;
	bool is_filter_display = false;
	bool verbose = false;
	bool list_flds = false;
	bool print_progress = false;
	bool compress = false;
	sinsp_evt::param_fmt event_buffer_format = sinsp_evt::PF_NORMAL;
	sinsp_filter* display_filter = NULL;
	double duration = 1;
	captureinfo cinfo;
	string output_format;
	uint32_t snaplen = 0;
	int long_index = 0;
	int32_t n_filterargs = 0;
	int cflag = 0;
	bool jflag = false;
	string cname;
	vector<summary_table_entry>* summary_table = NULL;
	string timefmt = "%evt.time";
	vector<sinsp_table> tables;

	// These variables are for the cycle_writer engine
	int duration_seconds = 0;	
	int rollover_mb = 0;
	int file_limit = 0;
	bool do_cycle = false;

	static struct option long_options[] =
	{
		{"print-ascii", no_argument, 0, 'A' },
		{"print-base64", no_argument, 0, 'b' },
#ifdef HAS_CHISELS
		{"chisel", required_argument, 0, 'c' },
		{"list-chisels", no_argument, &cflag, 1 },
#endif
		{"displayflt", no_argument, 0, 'd' },
		{"debug", no_argument, 0, 'D'},
		{"exclude-users", no_argument, 0, 'E' },
		{"fatfile", no_argument, 0, 'F'},
#ifndef DISABLE_CGW
		{"seconds", required_argument, 0, 'G' },
#endif
		{"help", no_argument, 0, 'h' },
#ifdef HAS_CHISELS
		{"chisel-info", required_argument, 0, 'i' },
#endif
#ifndef DISABLE_CGW
		{"file-size", required_argument, 0, 'C' },
#endif
		{"json", no_argument, 0, 'j' },
		{"list", no_argument, 0, 'l' },
		{"list-events", no_argument, 0, 'L' },
		{"numevents", required_argument, 0, 'n' },
		{"progress", required_argument, 0, 'P' },
		{"print", required_argument, 0, 'p' },
		{"quiet", no_argument, 0, 'q' },
		{"readfile", required_argument, 0, 'r' },
		{"snaplen", required_argument, 0, 's' },
		{"summary", no_argument, 0, 'S' },
		{"timetype", required_argument, 0, 't' },
		{"verbose", no_argument, 0, 'v' },
		{"version", no_argument, 0, 0 },
		{"writefile", required_argument, 0, 'w' },
#ifndef DISABLE_CGW
		{"limit", required_argument, 0, 'W' },
#endif
		{"print-hex", no_argument, 0, 'x'},
		{"print-hex-ascii", no_argument, 0, 'X'},
		{"compress", no_argument, 0, 'z' },
		{0, 0, 0, 0}
	};

	output_format = "*%evt.num <TIME> %evt.cpu %proc.name (%thread.tid) %evt.dir %evt.type %evt.info";

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
                                        "Abc:"
#ifndef DISABLE_CGW
                                        "C:"
#endif
                                        "dDEF"
#ifndef DISABLE_CGW
                                        "G:"
#endif
                                        "hi:jlLn:Pp:qr:Ss:t:v"
#ifndef DISABLE_CGW
                                        "W:"
#endif
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
			case 0:
				if(cflag != 1 && cflag != 2)
				{
					break;
				}

				if(cflag == 2)
				{
					cname = optarg;
				}
#ifdef HAS_CHISELS
			case 'c':
				{
					if(cflag == 0)
					{
						string ostr(optarg);

						if(ostr.size() >= 1)
						{
							if(ostr == "l")
							{
								cflag = 1;
							}
						}
					}

					if(cflag == 1)
					{
						vector<chisel_desc> chlist;
						sinsp_chisel::get_chisel_list(&chlist);
						list_chisels(&chlist, true);
						delete inspector;
						return sysdig_init_res(EXIT_SUCCESS);
					}

					sinsp_chisel* ch = new sinsp_chisel(inspector, optarg);
					parse_chisel_args(ch, inspector, optind, argc, argv, &n_filterargs);
					g_chisels.push_back(ch);
				}
#endif
				break;

#ifndef DISABLE_CGW
			// File-size
			case 'C':
				rollover_mb = atoi(optarg);
				if(rollover_mb <= 0)
				{
					throw sinsp_exception(string("invalid file size") + optarg);
					res.m_res = EXIT_FAILURE;
					goto exit;
				}

				// -C always implicates a cycle
				do_cycle = true;
				break;
#endif

			case 'D':
				inspector->set_debug_mode(true);
				break;
			case 'E':
				inspector->set_import_users(false);
				break;
			case 'F':
				inspector->set_fatfile_dump_mode(true);
				break;
#ifndef DISABLE_CGW
			// Number of seconds between roll-over
			case 'G':
				duration_seconds = atoi(optarg);
				if(duration_seconds <= 0)
				{
					throw sinsp_exception(string("invalid duration") + optarg);
					res.m_res = EXIT_FAILURE;
					goto exit;
				}
				break;
#endif

#ifdef HAS_CHISELS
			// --chisel-info and -i
			case 'i':
				{
					cname = optarg;

					vector<chisel_desc> chlist;

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
			case 'h':
				usage();
				delete inspector;
				return sysdig_init_res(EXIT_SUCCESS);
			case 'l':
				list_flds = true;
				break;
			case 'L':
				list_events(inspector);
				delete inspector;
				return sysdig_init_res(EXIT_SUCCESS);
			case 'n':
				cnt = atoi(optarg);
				if(cnt <= 0)
				{
					throw sinsp_exception(string("invalid event count ") + optarg);
					res.m_res = EXIT_FAILURE;
					goto exit;
				}
				break;
			case 'P':
				print_progress = true;
				break;
			case 'p':
				if(string(optarg) == "p")
				{
					//
					// -pp shows the default output format, useful if the user wants to tweak it.
					//
					replace_in_place(output_format, "<TIME>", timefmt);
					printf("%s\n", output_format.c_str());
					delete inspector;
					return sysdig_init_res(EXIT_SUCCESS);
				}
				else if(string(optarg) == "c" || string(optarg) == "container")
				{
					output_format = "*%evt.num <TIME> %evt.cpu %container.name (%container.id) %proc.name (%thread.tid:%thread.vtid) %evt.dir %evt.type %evt.info";

					//
					// This enables chisels to determine if they should print container information
					//
					if ( inspector != NULL )
                                        {
                                           inspector->set_print_container_data( true );
                                        }
				}
				else
				{
					output_format = optarg;
				}

				break;
			case 'q':
				quiet = true;
				break;
			case 'r':
				infiles.push_back(optarg);
				break;
			case 'S':
				summary_table = new vector<summary_table_entry>;

				for(uint32_t j = 0; j < PPM_EVENT_MAX; j++)
				{
					summary_table->push_back(summary_table_entry(j, false));
				}

				for(uint32_t j = 0; j < PPM_SC_MAX * 2; j++)
				{
					summary_table->push_back(summary_table_entry(j, true));
				}

				break;
			case 's':
				snaplen = atoi(optarg);
				break;
			case 't':
				{
					string tms(optarg);

					if(tms == "h")
					{
						timefmt = "%evt.time";
					}
					else if(tms == "a")
					{
						timefmt = "%evt.rawtime.s.%evt.rawtime.ns";
					}
					else if(tms == "r")
					{
						timefmt = "%evt.reltime.s.%evt.reltime.ns";
					}
					else if(tms == "d")
					{
						timefmt = "%evt.latency.s.%evt.latency.ns";
					}
					else if(tms == "D")
					{
						timefmt = "%evt.deltatime.s.%evt.deltatime.ns";
					}
					else
					{
						fprintf(stderr, "invalid modifier for flag -t\n");
						delete inspector;
						return sysdig_init_res(EXIT_FAILURE);
					}
				}
				break;
			case 'v':
				verbose = true;
				break;
			case 'w':
				outfile = optarg;
				quiet = true;
				break;

#ifndef DISABLE_CGW
			// Number of capture files to cycle through
			case 'W':
				file_limit = atoi(optarg);
				if(file_limit <= 0)
				{
					throw sinsp_exception(string("invalid file limit") + optarg);
					res.m_res = EXIT_FAILURE;
					goto exit;
				}
				break;
#endif

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
			default:
				break;
			}

			if(string(long_options[long_index].name) == "version")
			{
				printf("sysdig version %s\n", SYSDIG_VERSION);
				delete inspector;
				return sysdig_init_res(EXIT_SUCCESS);
			}
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
			if(verbose)
			{
				//
				// -ll shows the fields verbosely, i.e. with more information
				// like the type
				//
				list_fields(true);
			}
			else
			{
				list_fields(false);
			}

			res.m_res = EXIT_SUCCESS;
			goto exit;
		}

		string filter;

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

			if(is_filter_display)
			{
				display_filter = new sinsp_filter(inspector, filter);
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
		// Insert the right time format based on the -t flag
		//
		replace_in_place(output_format, "<TIME>", timefmt);

		//
		// Create the event formatter
		//
		sinsp_evt_formatter formatter(inspector, output_format);

		//
		// Set output buffers len
		//
		if(!verbose && g_chisels.size() == 0)
		{
			inspector->set_max_evt_output_len(80);
		}

		for(uint32_t j = 0; j < infiles.size() || infiles.size() == 0; j++)
		{
#ifdef HAS_FILTERING
			if(filter.size() && !is_filter_display)
			{
				inspector->set_filter(filter);
			}
#endif

			//
			// Launch the capture
			//
			bool open_success = true;

			if(infiles.size() != 0)
			{
				initialize_chisels();

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

				initialize_chisels();

				//
				// No file to open, this is a live capture
				//
#if defined(HAS_CAPTURE)
				if(print_progress)
				{
					fprintf(stderr, "the -P flag cannot be used with live captures.\n");
					res.m_res = EXIT_FAILURE;
					goto exit;
				}

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
			}

			if(snaplen != 0)
			{
				inspector->set_snaplen(snaplen);
			}

			duration = ((double)clock()) / CLOCKS_PER_SEC;

			if(outfile != "")
			{
				inspector->setup_cycle_writer(outfile, rollover_mb, duration_seconds, file_limit, do_cycle, compress);
				inspector->autodump_next_file();
			}

//sinsp_table table(inspector);
//tables.push_back(table);
//tables[0].configure("*proc.pid proc.name evt.buflen evt.num");

			//
			// Notify the chisels that the capture is starting
			//
			chisels_on_capture_start();

			cinfo = do_inspect(inspector,
				cnt,
				quiet,
				jflag,
				print_progress,
				display_filter,
				summary_table,
				&formatter,
				&tables);

			duration = ((double)clock()) / CLOCKS_PER_SEC - duration;

			scap_stats cstats;
			inspector->get_capture_stats(&cstats);

			if(verbose)
			{
				fprintf(stderr, "Driver Events:%" PRIu64 "\nDriver Drops:%" PRIu64 "\n",
					cstats.n_evts,
					cstats.n_drops);

				fprintf(stderr, "Elapsed time: %.3lf, Captured Events: %" PRIu64 ", %.2lf eps\n",
					duration,
					cinfo.m_nevts,
					(double)cinfo.m_nevts / duration);
			}

			//
			// Done. Close the capture.
			//
			inspector->close();

		}
	}
	catch(sinsp_capture_interrupt_exception&)
	{
		handle_end_of_file(print_progress);
	}
	catch(sinsp_exception& e)
	{
		cerr << e.what() << endl;
		handle_end_of_file(print_progress);
		res.m_res = EXIT_FAILURE;
	}
	catch(...)
	{
		handle_end_of_file(print_progress);
		res.m_res = EXIT_FAILURE;
	}

exit:
	//
	// If any of the chisels is requesting another run,
	//
	for(vector<sinsp_chisel*>::iterator it = g_chisels.begin();
		it != g_chisels.end(); ++it)
	{
		string na;
		if((*it)->get_nextrun_args(&na))
		{
			res.m_next_run_args = sinsp_split(na, ' ');
		}
	}

	//
	// If there's a summary table, sort and print it
	//
	if(summary_table != NULL)
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

//#ifdef SYSTOP
#if 1
	
captureinfo do_systop_inspect(sinsp* inspector,
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
		else if(res == SCAP_EOF)
		{
			break;
		}
		else if(res != SCAP_SUCCESS)
		{
			//
			// Event read error.
			// Notify the chisels that we're exiting, and then die with an error.
			//
			cerr << "res = " << res << endl;
			throw sinsp_exception(inspector->getlasterr().c_str());
		}

		if(ui->process_event(ev) == true)
		{
			return retval;
		}

		retval.m_nevts++;
	}

	return retval;
}

sysdig_init_res systop_init(int argc, char **argv)
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

	static struct option long_options[] =
	{
		{"exclude-users", no_argument, 0, 'E' },
		{"help", no_argument, 0, 'h' },
		{"numevents", required_argument, 0, 'n' },
		{"readfile", required_argument, 0, 'r' },
		{"snaplen", required_argument, 0, 's' },
		{"version", no_argument, 0, 0 },
		{0, 0, 0, 0}
	};

	//
	// Initialize ncurses
	//
#ifndef NOCURSESUI
	(void) initscr();      // initialize the curses library
	keypad(stdscr, TRUE);  // enable keyboard mapping
	(void) nonl();         // tell curses not to do NL->CR/NL on output
	intrflush(stdscr, false);
	keypad(stdscr, true);
	curs_set(0);
	if (has_colors()) {
	  start_color();
	}
	use_default_colors();
	mousemask(ALL_MOUSE_EVENTS, NULL);
	noecho();
	timeout(0);
	raw();
#endif

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
                                        "Ehn:r:s:", long_options, &long_index)) != -1)
		{
			switch(op)
			{
			case 'E':
				inspector->set_import_users(false);
				break;
			case 'h':
				usage();
				delete inspector;
				return sysdig_init_res(EXIT_SUCCESS);
			case 'n':
				cnt = atoi(optarg);
				if(cnt <= 0)
				{
					throw sinsp_exception(string("invalid event count ") + optarg);
					res.m_res = EXIT_FAILURE;
					goto exit;
				}
				break;
			case 'r':
				infiles.push_back(optarg);
				break;
			case 's':
				snaplen = atoi(optarg);
				break;
			default:
				break;
			}

			if(string(long_options[long_index].name) == "version")
			{
				printf("sysdig version %s\n", SYSDIG_VERSION);
				delete inspector;
				return sysdig_init_res(EXIT_SUCCESS);
			}
		}

		string filter;

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


		for(uint32_t j = 0; j < infiles.size() || infiles.size() == 0; j++)
		{
#ifdef HAS_FILTERING
			if(filter.size())
			{
				inspector->set_filter(filter);
			}
#endif

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
			}

			if(snaplen != 0)
			{
				inspector->set_snaplen(snaplen);
			}

			//
			// Initialize the UI
			//
			sinsp_cursesui ui(inspector);

			vector<sinsp_table_info> views;

			vector<string> at_all;
			at_all.push_back("");
			at_all.push_back("evt.type");
			vector<string> at_proc;
			at_proc.push_back("proc.pid");
			at_proc.push_back("proc.name");
			at_proc.push_back("thread.tid");

			int32_t cs [] = {-1, 9, 12, 6, 12, 12, 200};
			vector<int32_t> csv (cs, cs + sizeof(cs) / sizeof(cs[0]));
			views.push_back(sinsp_table_info("top processes", 
				"*proc.pid proc.pid user.name proc.nchilds proc.vmsize proc.vmrss proc.cmdline", 
				at_all,
				2,
				"",
				&csv,
				"proc.name=apache2"));
			views.push_back(sinsp_table_info("top containers",
				"*proc.pid proc.pid proc.name container.name proc.vmsize proc.vmrss evt.num", 
				at_all,
				2,
				"*3 3 S4",
				NULL,
				""));
			views.push_back(sinsp_table_info("top syscalls", "*evt.type evt.type Sevt.count", at_proc, 2, "", NULL, ""));
			views.push_back(sinsp_table_info("top FDs", "*fd.name fd.name Sevt.count", at_proc, 2, "", NULL, ""));

			ui.configure(&views);
			ui.start();

//			bool dd = ui.drilldown("proc.pid", "3564");
//			string flt = ui.m_sel_hierarchy.tofilter();
//			dd = ui.drilldown("evt.type", "open");
//			flt = ui.m_sel_hierarchy.tofilter();

			cinfo = do_systop_inspect(inspector,
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
	endwin();
#endif

	if(errorstr != "")
	{
		cerr << errorstr << endl;
	}

	return res;
}
#endif

//
// MAIN
//
int main(int argc, char **argv)
{
	sysdig_init_res res;

//
	res = systop_init(argc, argv);
	return 0;
//
#ifdef SYSTOP
	string fullcmd(argv[0]);
	uint32_t sz = sizeof("systop") - 1;

	if(fullcmd.size() >= sz)
	{
		if(fullcmd.substr(fullcmd.size() - sz, sz) == "systop")
		{
			res = systop_init(argc, argv);
			return 0;
		}
	}
#endif
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
		vector<char*> newargv;

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
