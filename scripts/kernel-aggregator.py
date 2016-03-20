#!/usr/bin/python

#
# The aim of this script is reading in input a JSON containing all links found
# by the crawler, remove duplicated ones and aggregating them by package (which,
# in most cases, is nothig but the kernel version).
# It then proceeds to call the kerner-downloader with links and other infos.
#

import sys
import json
import urllib2

from subprocess import Popen, PIPE, call

#
# This points to the kernel downloader script.
# In a standard scenario, arguments to the command line will be
#  > $DISTRO $VERSION [...$URL]
# where $URL is an ellipsis of links to file to download as specified in the
# aggregation rules below.
# Different cases may lead to different configurations; see aggregation rules.
#
kernel_downloader = "./kernel-downloader.sh"

# This script reads a JSON of links from the stdin channel.
links = json.load(sys.stdin)

filename = "[^\/]*$"

# Thanks Python for giving me a shitty regex engine
def match(string, regex):
	p = Popen(["grep", "-E", "-o", regex], stdin=PIPE, stdout=PIPE)
	output = p.communicate(input=string)[0]
	line = output.decode().split("\n")[0]
	return line

def coreos_version(url):
	version = match(url, "[0-9]+\.[0-9]+\.[0-9]+|current")

	if version == "current":
		root = match(url, "^.*\/")
		version_info = urllib2.urlopen(root + "version.txt").read()
		version_info = match(version_info, "^COREOS_VERSION_ID.*$")
		version = version_info.split("=")[1]

	return version

#
# A set of rules for aggregating links in packages. Each distro has its own.
# `uniqueness` : regex or function
#   This is a parameter for determining when two links should be considered
#   pointing to identical files. In most cases, filename is enough, so this
#   parameter can just be a regex. However, some particular distros (such as
#   CoreOS) require a further action that cannot be resolved simply with a
#   regex. In those cases, we use a function that, given the URL, returns an
#   unique identifier.
# `version` : regex or function
#   This parameter is used to determine when two files belong to the same
#   "package". Most of times file names contain the package version so, in such
#   cases, we can just use a regex to match the file name against the package
#   version. But not all distros follow this logic (again, CoreOS breaks it)
#   so we can use a function that, given the URL returns the package version (or
#   package identifier).
#   But Debian goes further breaking this logic, so, instead of trying to
#   aggregate, we just don't care about packages at this level. This result is
#   achieved simply by setting `version` to an empty string, which means
#   considering every link as part of the same package. This behaviour simplify
#   this script's logic, but requires a custom download function to be written
#   in the kernel-downloader (for maximum argv size, see `$ getconf ARG_MAX`)
#   In the same way, setting `version` to "filename" will result in considering
#   each file as part of a different package.
#
rules = {
	"Ubuntu" : {
		"uniqueness" : filename,
		"version" : "[0-9]{1}\.[0-9]+\.[0-9]+-[0-9]+\.[0-9]+"
	},

	"Fedora" : {
		"uniqueness" : filename,
		"version" : "[0-9]+\.[0-9]+.[0-9]+\-[0-9]+\.fc[0-9]+"
	},

	"CoreOS" : {
		"uniqueness" : coreos_version,
		"version" : coreos_version
	},

	"CentOS" : {
		"uniqueness" : filename,
		"version" : "[0-9]+\.[0-9]+\.[0-9]+\-[0-9]+(\.[0-9]+\.[0-9]+(\.[0-9]+(\.[0-9]+)?)?)?\.el[0-9]+"
	},

	"Debian" : {
		"uniqueness" : filename,
		"version" : ""
	}
}

packages = {}
for distro, rule in rules.iteritems():
	files = {}
	versions = {}

	for url in links[distro]:
		unique = None

		if isinstance(rule["uniqueness"], basestring):
			unique = match(url, rule["uniqueness"])
		else:
			unique = rule["uniqueness"](url)

		if not unique in files:
			files[unique] = url

	for unique, link in files.iteritems():
		version = ""

		if isinstance(rule["version"], basestring):
			version = match(link, rule["version"])
		else:
			version = rule["version"](link)

		if not version in versions:
			versions[version] = []

		versions[version].append(link)

	packages[distro] = versions


for distro, versions in packages.iteritems():
	for number, links in versions.iteritems():
		call([kernel_downloader, distro, number] + links)
