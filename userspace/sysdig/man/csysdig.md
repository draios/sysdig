NAME
----

csysdig - the ncurses user interface for sysdig

SYNOPSIS
--------

**sysdig** [*option*]... [*filter*]

DESCRIPTION
-----------

csysdig exports sysdig's functionality through an intuitive and powerful ncurses-bases user interface. For more information about sysdig, refer to its man page.

csysdig has been designed to mimic tools like **top** and **htop**, but it offers much richer functionality, based on these key concepts:

1. Support for both live analysis and sysdig trace files. Trace files can come from the same machine or from another machine. 
2. Visibility into many classes of resources, including CPU, memory, disk I/O, network I/O.
3. Ability to drill down into a selection (e.g. a process, a file, a network connection) to get more information about it.
4. Full customization support.
5. Container support.

csysdig works on any terminal, and has support for terminal colors and mouse input.

csysdig includes support for sysdig's powerul filtering language.

**Views**  

csysdig is based on the concept of 'views', Lua scripts that determine how metrics are collected, processed and represented on screen. Views are located in the sysdig chisel directory path,
usually */usr/share/sysdig/chisels* and *~/.chisels*. You can edit the views in those folders to customize their behavior, or you can add new views for your specific needs.  


BASIC USAGE
-----------

If you are familiar with top and htop, csysdig's UI should feel pretty natural to use. However, keep in mind that:

1. If you run csysdig without arguments, it will display live system data, updating every 2 seconds. To analyze a trace file, use the -r command line flag.
2. You can switch to a different view by using the _F2_ key.
3. You can to drill down into a selection by typing _enter_. You can navigate back by typing _backspace_.
4. You can observe reads and writes (_F5_) or see sysdig events (_F6_) for any selection.

OPTIONS
-------
  
**-d** _period_, **--delay**=_period_  
  Set the delay between updates, in milliseconds. This works similarly to the -d option in top.  

**-E**, **--exclude-users**  
  Don't create the user/group tables by querying the OS when sysdig starts. This also means that no user or group info will be written to the tracefile by the -w flag. The user/group tables are necessary to use filter fields like user.name or group.name. However, creating them can increase sysdig's startup time. Moreover, they contain information that could be privacy sensitive.  

**-h**, **--help**  
  Print this page
  
**--logfile** _file_        
  Print program logs into the given file.
  
**-n** _num_, **--numevents**=_num_  
  Stop capturing after _num_ events

**-pc**, **-pcontainers**_  
  Instruct csysdig to use a container-friendly format in its views. This will cause several of the views to contain additional container-related columns.

**-r** _readfile_, **--read**=_readfile_  
  Read the events from _readfile_.
  
**-s** _len_, **--snaplen**=_len_  
  Capture the first _len_ bytes of each I/O buffer. By default, the first 80 bytes are captured. Use this option with caution, it can generate huge trace files.

**-v** _view_id_, **--views**=_view_id_  
  Run the view with the given ID when csysdig starts. View IDs can be found in the view documentation pages in csysdig. Combine  this option with a command line filter for complete output customization.

**--version**  
  Print version number.
    
FILES
-----

*/usr/share/sysdig/chisels*  
  The global chisels directory.

*~/.chisels*  
  The personal chisels directory.

AUTHOR
------

sysdig inc. <info@sysdigcloud.com>

SEE ALSO
--------

**sysdig**(8), **strace**(8), **tcpdump**(8), **lsof**(8)
