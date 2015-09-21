![](https://ga-beacon.appspot.com/UA-40398182-5/sysdig/README?pixel)

sysdig
======

[![Build Status](https://travis-ci.org/draios/sysdig.png?branch=master)](https://travis-ci.org/draios/sysdig)

#Welcome to **sysdig**!

**Sysdig** is a universal system visibility tool with native support for containers:  
`~$ sysdig`

**Csysdig** is a simple, intuitive, and fully customizable curses UI for sysdig:  
`~$ csysdig`

Where to start?
---
If this is your first time hearing about sysdig, we recommend you [start with the website] (http://www.sysdig.org).  
  
What does sysdig do and why should I use it?
---
**Sysdig is a simple tool for deep system visibility, with native support for containers.**

We built sysdig to give you _easy access_ to the actual behavior of your Linux systems and containers. Honestly, the best way to understand sysdig is to [try it] (http://www.sysdig.org/install/) - its super easy! Or here's a quick video introduction to csysdig, the simple, intuitive, and fully customizable curses-based UI for sysdig: https://www.youtube.com/watch?v=UJ4wVrbP-Q8

Far too often, system-level monitoring and troubleshooting still involves logging into a machine with SSH and using a plethora of dated tools with very inconsistent interfaces. And many of these classic Linux tools breakdown completely in containerized environments. Sysdig unites your Linux toolkit into a single, consistent, easy-to-use interface. And sysdig's unique architecture allows deep inspection into containers, right out of the box, without having to instrument the containers themselves in any way.

Sysdig instruments your physical and virtual machines at the OS level by installing into the Linux kernel and capturing system calls and other OS events. Sysdig also makes it possible to create trace files for system activity, similarly to what you can do for networks with tools like tcpdump and Wireshark. This way, problems can be analyzed at a later time, without losing important information. Rich system state is stored in the trace files, so that the captured activity can be put into full context.

Think about sysdig as strace + tcpdump + htop + iftop + lsof + ...awesome sauce.

Documentation / Support
---
[Visit the wiki] (https://github.com/draios/sysdig/wiki) for full documentation on sysdig and its APIs.  

For support using sysdig, please contact [the official mailing list] (https://groups.google.com/forum/#!forum/sysdig).  

Join the Community
---
* Contact the [official mailing list] (https://groups.google.com/forum/#!forum/sysdig) for support and to talk with other users
* Follow us on [Twitter] (https://twitter.com/sysdig) for the Chisel of the Week
* This is our [blog] (http://sysdigcloud.com/blog/). There are many like it, but this one is ours.
* Join our IRC channel `#sysdig` on [Freenode](http://webchat.freenode.net/?channels=sysdig)

Sysdig Cloud
---
Interested in a fully supported, fully distributed version of sysdig? Check out [Sysdig Cloud] (http://sysdig.com)!

Sysdig is proudly supported by [Sysdig Inc] (http://sysdig.com/).  

Interested in what we're doing? [Sysdig is hiring] (http://sysdig.com/jobs/).
