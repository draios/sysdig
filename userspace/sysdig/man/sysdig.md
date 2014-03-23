NAME
----

sysdig - the definitive system and process troubleshooting tool

SYNOPSIS
--------

**sysdig** [*option*]... [*filter*]

DESCRIPTION
-----------

sysdig is a tool for system troubleshooting, analysis and exploration. It can be used to capture, filter and decode system calls and other OS events. 
sysdig can be both used to inspect live systems, or to generate trace files that can be analyzed at a later stage.

Sysdig includes a powerul filtering language, has customizable output, and can be extended through Lua scripts, called chisels.

**Output format**

By default, sysdig prints the information for each captured event on a single line, with the following format:

```<evt.time> <evt.cpu> <proc.name> <thread.tid> <evt.dir> <evt.type> <evt.args>```

where:
* evt.time is the event timestamp
* evt.cpu is the CPU number where the event was captured
* proc.name is the name of the process that generated the event
* thread.tid id the TID that generated the event, which corresponds to the PID for single thread processes
* evt.dir is the event direction, > for enter events and < for exit events
* evt.type is the name of the event, e.g. 'open' or 'read'
* evt.args is the list of event arguments.

The output format can be customized with the -p switch, using any of the fields listed by 'sysdig -l'.

**Filtering**  

sysdig filters are specified at the end of the command line. The simplest filter is a simple field-value check:
> $ sysdig proc.name=cat

The list of available fields can be obtained with 'sysdig -l'.
Checks can use one of these comparison operators: _=_, _!=_, _<_, _<=_, _>_, _>=_ and _contains_. e.g.
> $ sysdig fd.name contains /etc

Multiple checks can be combined through brakets and the following boolean operators: _and_, _or_, _not_. e.g.
> $ sysdig "not(fd.name contains /proc or fd.name contains /dev)"

**Chisels**  
Sysdig's chisels are little scripts that analyze the sysdig event stream to perform useful actions.
To get the list of available chisels, type
> $ sysdig -cl  

For each chisel, you get the description and the list of arguments it expects. 
To run one of the chisels, you use the -c flag, e.g.:
> $ sysdig -c topfiles

If a chisel needs arguments, you specify them after the chisel name:
> $ sysdig -c spy_ip 192.168.1.157

Chiesls can be combined with filters:
> $ sysdig -c topfiles "not fd.name contains /dev"

OPTIONS
-------

**-a**, **--abstime**  
  Show absolute event timestamps
  
**-c** _chiselname_ _chiselargs_, **--chisel**=_chiselname_ _chiselargs_  
  run the specified chisel. If the chisel require arguments, they must be specified in the command line after the name.
  
**-cl**, **--list-chisels**  
  lists the available chisels. Looks for chisels in ., ./chisels, ~/chisels and /usr/share/sysdig/chisels.
  
**-d**, **--displayflt**  
  Make the given filter a display one Setting this option causes the events to be filtered after being parsed by the state system. Events are normally filtered before being analyzed, which is more efficient, but can cause state (e.g. FD names) to be lost
  
**-h**, **--help**  
  Print this page
  
**-j**, **--json**         
  Emit output as json
  
**-l**, **--list**  
  List the fields that can be used for filtering and output formatting. Use -lv to get additional information for each field.
  
**-L**, **--list-events**  
  List the events that the engine supports
  
**-n** _num_, **--numevents**=_num_  
  Stop capturing after <num> events
  
**-p** _output_format_, **--print**=_output_format_  
  Specify the format to be used when printing the events. See the examples section below for more info.
  
**-q**, **--quiet**  
  Don't print events on the screen. Useful when dumping to disk.
  
**-r** _readfile_, **--read**=_readfile_  
  Read the events from <readfile>.
  
**-S**, **--summary**  
  print the event summary (i.e. the list of the top events) when the capture ends.
  
**-s** _len_, **--snaplen**=_len_  
  Capture the first <len> bytes of each I/O buffer. By default, the first 80 bytes are captured. Use this option with caution, it can generate huge trace files.

**-t** _timetype_, **--timetype**=_timetype_  
  Change the way event time is diplayed. Accepted values are **h** for human-readable string, **a** for abosulte timestamp from epoch, **r** for relative time from the beginning of the capture, and **d** for delta between event enter and exit.
  
**-T**, **--print-text**  
  Print only the text portion of data buffers, and echo EOLS. This is useful to only display human-readable data.
  
**-v**, **--verbose**  
  Verbose output.
  
**-w** _writefile_, **--write**=_writefile_  
  Write the captured events to _writefile_.

**-x**, **--print-hex**  
  Print data buffers in hex.
  
**-X**, **--print-hex-ascii**  
  Print data buffers in hex and ASCII.
  
EXAMPLES
--------
Capture all the events from the live system and print them to screen
> $ sysdig

Capture all the events from the live system and save them to disk
> $ sysdig -qw dumpfile.scap

Read events from a file and print them to screen
> $ sysdig -r dumpfile.scap

Print all the open system calls invoked by cat
> $ sysdig proc.name=cat and evt.type=open

Print the name of the files opened by cat
> $ ./sysdig -p"%evt.arg.name" proc.name=cat and evt.type=open

List the available chisels
> $ ./sysdig -cl

Run the spy_ip chisel for the 192.168.1.157 IP address:
> $ sysdig -c spy_ip 192.168.1.157

FILES
-----

*/opt/sysdig/chisels*  
  The global chisels directory.

*~/.chisels*  
  The personal chisels directory.

BUGS
----

Bugs?

AUTHOR
------

Draios inc. <info@draios.com>

SEE ALSO
--------

**strace**(8), **tcpdump**(8), **lsof**(8)
