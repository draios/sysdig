NAME
----

sysdig - Interactively dump and analyze system calls

SYNOPSIS
--------

**sysdig** [*option*]... [*filter*]

DESCRIPTION
-----------

sysdig is a system call and system event analyzer.

OPTIONS
-------

**-a**, **--abstime**
  Show absolute event timestamps
  
**-c** <chiselname> <chiselargs>, **--chisel**=<chiselname> <chiselargs>
  run the specified chisel. If the chisel require arguments, they must be specified in the command line after the name.
  
**-cl**, **--list-chisels**
  lists the available chisels. Looks for chisels in ., ./chisels, ~/chisels and /usr/share/sysdig/chisels.
  
**-dv**, **--displayflt**   
  Make the given filter a dsiplay one Setting this option causes the events to be filtered after being parsed by the state system. Events are normally filtered before being analyzed, which is more efficient, but can cause state (e.g. FD names) to be lost
  
**-h**, **--help**
  Print this page
  
**-j**, **--json**         
  Emit output as json
  
**-l**, **--list**
  List the fields that can be used for filtering and output formatting. Use -lv to get additional information for each field.
  
**-L**, **--list-events**  
  List the events that the engine supports
  
**-n** <num>, **--numevents**=<num>
  Stop capturing after <num> events
  
**-p** <output_format>, **--print**=<output_format>
  Specify the format to be used when printing the events. See the examples section below for more info.
  
**-q**, **--quiet**
  Don't print events on the screen. Useful when dumping to disk.
  
**-r** <readfile>, **--read**=<readfile>
  Read the events from <readfile>.
  
**-S**, **--summary**
  print the event summary (i.e. the list of the top events) when the capture ends.
  
**-s** <len>, **--snaplen**=<len>
  Capture the first <len> bytes of each I/O buffer. By default, the first 80 bytes are captured. Use this option with caution, it can generate huge trace files.
  
**-v**, **--verbose**
  Verbose output
  
**-w** <writefile>, **--write**=<writefile>
  Write the captured events to <writefile>.

FILES
-----

*/opt/sysdig/chisels*
  The global chisel directory.

*~/.chisels*
  The user chisel directory.

BUGS
----

Bugs?

AUTHOR
------

Draios inc. <info@draios.com>

SEE ALSO
--------

strace(8)
