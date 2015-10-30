NAME
----

sysdig - the definitive system and process troubleshooting tool

SYNOPSIS
--------

**sysdig** [*option*]... [*filter*]

DESCRIPTION
-----------

**Note: if you are interested in an easier to use interface for the sysdig functionality, use the csysdig command line utility.**

sysdig is a tool for system troubleshooting, analysis and exploration. It can be used to capture, filter and decode system calls and other OS events. 
sysdig can be both used to inspect live systems, or to generate trace files that can be analyzed at a later stage.

sysdig includes a powerul filtering language, has customizable output, and can be extended through Lua scripts, called chisels.

**Output format**

By default, sysdig prints the information for each captured event on a single line, with the following format:

```*%evt.num %evt.time %evt.cpu %proc.name (%thread.tid) %evt.dir %evt.type %evt.info```

where:
* evt.num is the incremental event number
* evt.time is the event timestamp
* evt.cpu is the CPU number where the event was captured
* proc.name is the name of the process that generated the event
* thread.tid id the TID that generated the event, which corresponds to the PID for single thread processes
* evt.dir is the event direction, > for enter events and < for exit events
* evt.type is the name of the event, e.g. 'open' or 'read'
* evt.args is the list of event arguments.

The output format can be customized with the -p switch, using any of the fields listed by 'sysdig -l'.

Using -pc or -pcontainer, the default format will be changed to a container-friendly one:

```*%evt.num %evt.time %evt.cpu %container.name (%container.id) %proc.name (%thread.tid:%thread.vtid) %evt.dir %evt.type %evt.info```

**Trace Files**  

A trace file can be created using the -w switch:
> $ sysdig -w trace.scap

The -s switch can be used to specify how many bytes of each data buffer should be saved to disk. And filters can be
used to save only certain events to disk: 
> $ sysdig -s 2000 -w trace.scap proc.name=cat

Trace files can be read this using the -r switch: 
> $ sysdig -r trace.scap

**Filtering**  

sysdig filters are specified at the end of the command line. The simplest filter is a basic field-value check:
> $ sysdig proc.name=cat

The list of available fields can be obtained with 'sysdig -l'.
Filter expressions can use one of these comparison operators: _=_, _!=_, _<_, _<=_, _>_, _>=_, _contains_, _in_ and _exists_. e.g.
> $ sysdig fd.name contains /etc
> $ sysdig "evt.type in ( 'select', 'poll' )"
> $ sysdig proc.name exists

Multiple checks can be combined through brackets and the following boolean operators: _and_, _or_, _not_. e.g.
> $ sysdig "not (fd.name contains /proc or fd.name contains /dev)"

**Chisels**  

sysdig's chisels are little scripts that analyze the sysdig event stream to perform useful actions.
To get the list of available chisels, type
> $ sysdig -cl  

To get details about a specific chisel, type
> $ sysdig -i spy_ip

To run one of the chisels, you use the -c flag, e.g.
> $ sysdig -c topfiles_bytes

If a chisel needs arguments, you specify them after the chisel name:
> $ sysdig -c spy_ip 192.168.1.157

If a chisel has more than one argument, specify them after the chisel name, enclosed in quotes:
> $ sysdig -c chisel_name "arg1 arg2 arg3"

Chisels can be combined with filters:
> $ sysdig -c topfiles_bytes "not fd.name contains /dev"

OPTIONS
-------

**-A**, **--print-ascii**  
  Only print the text portion of data buffers, and echo end-of-lines. This is useful to only display human-readable data.

**-b**, **--print-base64**  
  Print data buffers in base64. This is useful for encoding binary data that needs to be used over media designed to handle textual data (i.e., terminal or json).
    
**-c** _chiselname_ _chiselargs_, **--chisel**=_chiselname_ _chiselargs_  
  run the specified chisel. If the chisel require arguments, they must be specified in the command line after the name.

**-C** _filesize_  
  Break a capture into separate files, and limit the size of each file based on the specified number of megabytes. The units of _filesize_ are millions of bytes (10^6, not 2^20). Use in conjunction with **-W** to enable automatic file rotation. Otherwise, new files will continue to be created until the capture is manually stopped. 
  
  Files will have the name specified by **-w** with a counter added starting at 0.
  
**-cl**, **--list-chisels**  
  lists the available chisels. Looks for chisels in ./chisels, ~/.chisels and /usr/share/sysdig/chisels.
  
**-d**, **--displayflt**  
  Make the given filter a display one. Setting this option causes the events to be filtered after being parsed by the state system. Events are normally filtered before being analyzed, which is more efficient, but can cause state (e.g. FD names) to be lost.
  
**-D**, **--debug**  
  Capture events about sysdig itself

**-E**, **--exclude-users**  
  Don't create the user/group tables by querying the OS when sysdig starts. This also means that no user or group info will be written to the tracefile by the **-w** flag. The user/group tables are necessary to use filter fields like user.name or group.name. However, creating them can increase sysdig's startup time. Moreover, they contain information that could be privacy sensitive.

**-e** _numevents_  
  Break a capture into separate files, and limit the size of each file based on the specified number of events. Use in conjunction with **-W** to enable automatic file rotation. Otherwise, new files will continue to be created until the capture is manually stopped.
  
  Files will have the name specified by **-w** with a counter added starting at 0.

**-F**, **--fatfile**  
  Enable fatfile mode. When writing in fatfile mode, the output file will contain events that will be invisible when reading the file, but that are necessary to fully reconstruct the state. Fatfile mode is useful when saving events to disk with an aggressive filter. The filter could drop events that would the state to be updated (e.g. clone() or open()). With fatfile mode, those events are still saved to file, but 'hidden' so that they won't appear when reading the file. Be aware that using this flag might generate substantially bigger traces files.

**-G** _numseconds_  
  Break a capture into separate files, and limit the size of each file based on the specified number of seconds. Use in conjunction with **-W** to enable automatic file rotation. Otherwise, new files will continue to be created until the capture is manually stopped. 
  
  Files will have the name specified by **-w** which should include a time format as defined by strftime(3). If no time format is specified, a counter will be used.

**-h**, **--help**  
  Print this page
  
**-j**, **--json**         
  Emit output as json, data buffer encoding will depend from the print format selected.
  
**-i _chiselname_**, **--chisel-info=**_chiselname_  
  Get a longer description and the arguments associated with a chisel found in the -cl option list.

**-L**, **--list-events**  
  List the events that the engine supports
  
**-l**, **--list**  
  List the fields that can be used for filtering and output formatting. Use -lv to get additional information for each field.
    
**-N**
  Don't convert port numbers to names.

**-n** _num_, **--numevents**=_num_  
  Stop capturing after _num_ events

**-P**, **--progress**  
  Print progress on stderr while processing trace files.
  
**-p** _outputformat_, **--print**=_outputformat_  
  Specify the format to be used when printing the events. With -pc or -pcontainer will use a container-friendly format. See the examples section below for more info. Specifying **-pp** on the command line will cause sysdig to print the default command line format and exit.
  
**-q**, **--quiet**  
  Don't print events on the screen. Useful when dumping to disk.
  
**-r** _readfile_, **--read**=_readfile_  
  Read the events from _readfile_.
  
**-S**, **--summary**  
  print the event summary (i.e. the list of the top events) when the capture ends.
  
**-s** _len_, **--snaplen**=_len_  
  Capture the first _len_ bytes of each I/O buffer. By default, the first 80 bytes are captured. Use this option with caution, it can generate huge trace files.

**-t** _timetype_, **--timetype**=_timetype_  
  Change the way event time is displayed. Accepted values are **h** for human-readable string, **a** for absolute timestamp from epoch, **r** for relative time from the beginning of the capture, **d** for delta between event enter and exit, and **D** for delta from the previous event.
     
**--unbuffered**  
  Turn off output buffering. This causes every single line emitted by sysdig to be flushed, which generates higher CPU usage but is useful when piping sysdig's output into another process or into a script. 
  
**-v**, **--verbose**  
  Verbose output. This flag will cause the full content of text and binary buffers to be printed on screen, instead of being truncated to 40 characters. Note that data buffers length is still limited by the snaplen (refer to the -s flag documentation) -v will also make sysdig print some summary information at the end of the capture.
  
**--version**  
  Print version number.
  
**-w** _writefile_, **--write**=_writefile_  
  Write the captured events to _writefile_.

**-W** _num_  
  Turn on file rotation for continuous capture, and limit the number of files created to the specified number. Once the cap is reached, older files will be overwriten (ring buffer). Use in conjunction with the **-C** / **-G** / **-e** options to limit the size of each file based on number of megabytes, seconds, and/or events (respectively).

**-x**, **--print-hex**  
  Print data buffers in hex.
  
**-X**, **--print-hex-ascii**  
  Print data buffers in hex and ASCII.

**-z**, **--compress**  
  Used with **-w**, enables compression for tracefiles.
  
EXAMPLES
--------

Capture all the events from the live system and print them to screen
> $ sysdig

Capture all the events from the live system and save them to disk
> $ sysdig -w dumpfile.scap

Capture all the events in the latest 24 hours and save them to disk organized in files containing 1 hour of system activity each
> $ sysdig -G 3600 -W 24 -w dumpfile.scap

Read events from a file and print them to screen
> $ sysdig -r dumpfile.scap

Prepare a sanitized version of a system capture
> $ sysdig -r dumpfile.scap 'not evt.buffer contains foo' -w cleandump.scap

Print all the open system calls invoked by cat
> $ sysdig proc.name=cat and evt.type=open

Print the name of the files opened by cat
> $ sysdig -p"%evt.arg.name" proc.name=cat and evt.type=open

List the available chisels
> $ sysdig -cl

Use the spy_ip chisel to look at the data exchanged with 192.168.1.157:
> $ sysdig -c spy_ip 192.168.1.157

FILES
-----

*/usr/share/sysdig/chisels*  
  The global chisels directory.

*~/.chisels*  
  The personal chisels directory.

BUGS
----

* sysdig and its chisels are designed to be used with LuaJIT in Lua 5.1 mode. While it is possible to use sysdig with LuaJIT in Lua 5.2 mode or regular Lua, some chisels may not work as expected.

AUTHOR
------

Draios Inc. aka sysdig <info@sysdigcloud.com>

SEE ALSO
--------

**csysdig**(8), **strace**(8), **tcpdump**(8), **lsof**(8)
