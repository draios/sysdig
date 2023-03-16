sysdig
======
[![CI Build](https://github.com/draios/sysdig/actions/workflows/ci.yaml/badge.svg)](https://github.com/draios/sysdig/actions/workflows/ci.yaml) ![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/draios/sysdig)

<p align="center"><img src="https://raw.githubusercontent.com/draios/sysdig/dev/img/logo_large.png" width="360"></p>
<p align="center"><b>Dig Deeper</b></p>

<hr>

**Sysdig** is a universal system visibility tool with native support for containers:  
`~$ sysdig`

**Csysdig** is a simple, intuitive, and fully customizable curses UI for sysdig:  
`~$ csysdig`

Getting Started
---

Run Sysdig in a container:

```
sudo docker run --rm -i -t --privileged --net=host \
    -v /var/run/docker.sock:/host/var/run/docker.sock \
    -v /dev:/host/dev \
    -v /proc:/host/proc:ro \
    -v /boot:/host/boot:ro \
    -v /src:/src \
    -v /lib/modules:/host/lib/modules:ro \
    -v /usr:/host/usr:ro \
    -v /etc:/host/etc:ro \
    docker.io/sysdig/sysdig
```

And then run the `sysdig` or `csysdig` tool from the container shell!

Or install the [latest release](https://github.com/draios/sysdig/releases/latest) with a `deb` or `rpm` package for your distribution.

What does sysdig do and why should I use it?
---
**Sysdig is a simple tool for deep system visibility, with native support for containers.**

The best way to understand sysdig is to [try it](https://github.com/draios/sysdig/wiki/How-to-Install-Sysdig-for-Linux) - its super easy! Or here's a quick video introduction to csysdig, the simple, intuitive, and fully customizable curses-based UI for sysdig: https://www.youtube.com/watch?v=UJ4wVrbP-Q8

Far too often, system-level monitoring and troubleshooting still involves logging into a machine with SSH and using a plethora of dated tools with very inconsistent interfaces. And many of these classic Linux tools breakdown completely in containerized environments. Sysdig unites your Linux toolkit into a single, consistent, easy-to-use interface. And sysdig's unique architecture allows deep inspection into containers, right out of the box, without having to instrument the containers themselves in any way.

Sysdig instruments your physical and virtual machines at the OS level by installing into the Linux kernel and capturing system calls and other OS events. Sysdig also makes it possible to create trace files for system activity, similarly to what you can do for networks with tools like tcpdump and Wireshark. This way, problems can be analyzed at a later time, without losing important information. Rich system state is stored in the trace files, so that the captured activity can be put into full context.

Think about sysdig as strace + tcpdump + htop + iftop + lsof + ...awesome sauce.

Documentation / Support
---
[Visit the wiki](https://github.com/draios/sysdig/wiki) for full documentation on sysdig and its APIs.  

For support using sysdig, please contact [the official mailing list](https://groups.google.com/forum/#!forum/sysdig).  

Join the Community
---
* Contact the [official mailing list](https://groups.google.com/forum/#!forum/sysdig) for support and to talk with other users
* Follow us on [Twitter](https://twitter.com/sysdig)
* This is our [blog](https://sysdig.com/blog/). There are many like it, but this one is ours.
* Join our [Public Slack](https://slack.sysdig.com) channel for sysdig announcements and discussions.

Our [code of conduct](CODE_OF_CONDUCT.md) applies across all our projects and community places.

License Terms
---
The sysdig userspace programs and supporting code are licensed to you under the [Apache 2.0](./COPYING) open source license.

Developer Certification of Origin (DCO)
---
The Apache 2.0 license tells you what rights you have that are provided by the copyright holder. It is important that the contributor fully understands what rights they are licensing and agrees to them. Sometimes the copyright holder isn't the contributor, such as when the contributor is doing work on behalf of a company.

To make a good faith effort to ensure these criteria are met, we require the Developer Certificate of Origin (DCO) process to be followed.

The DCO is an attestation attached to every contribution made by every developer. In the commit message of the contribution, the developer simply adds a Signed-off-by statement and thereby agrees to the DCO, which you can find at http://developercertificate.org.

### DCO Sign-Off Methods
The DCO requires a sign-off message in the following format appear on each commit in the pull request:

```
Signed-off-by: John Doe <john.doe@sysdig.com>
```

You have to use your real name (sorry, no pseudonyms or anonymous contributions).

The DCO text can either be manually added to your commit body, or you can add either `-s` or `--signoff` to your usual `git commit` commands. If you are using the GitHub UI to make a change, you can add the sign-off message directly to the commit message when creating the pull request. If you forget to add the sign-off you can also amend a previous commit with the sign-off by running `git commit --amend -s`. If you've pushed your changes to GitHub already you'll need to force push your branch after this with `git push -f`.

Commercial Support
---
Interested in a fully supported, fully distributed version of sysdig? Check out [Sysdig Monitor](https://sysdig.com/products/monitor/)!

Open source sysdig is proudly supported by [Sysdig Inc](https://sysdig.com/company/).  

Interested in what we're doing? [Sysdig is hiring](https://sysdig.com/jobs/).

Reporting a vulnerability
---
Please refer to [SECURITY.md](SECURITY.md).
