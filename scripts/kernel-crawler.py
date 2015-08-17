#!/usr/bin/python

# Author: Samuele Pilleri
# Date: August 17th, 2015

import sys
import urllib2
from lxml import html

#
# This is the main configuration tree for easily analying Linux repositories
# hunting packages. When adding repos or so be sure to respect the same data
# structure
#
repos = {
	"CentOS" : [
		{
			# This is the root path of the repository in which the script will
			# look for distros (HTML page)
			"root" : "http://mirrors.kernel.org/centos/",

			# This is the XPath + Regex (optional) for analyzing the `root`
			# page and discover possible distro versions. Use the regex if you
			# want to limit the version release
			"discovery_pattern" : "/html/body//pre/a[regex:test(@href, '^6|7.*$')]/@href",

			# Once we have found every version available, we need to know were
			# to go inside the tree to find packages we need (HTML pages)
			"subdirs" : [
				"os/x86_64/Packages/",
				"updates/x86_64/Packages/"
			],

			# Finally, we need to inspect every page for packages we need.
			# Again, this is a XPath + Regex query so use the regex if you want
			# to limit the number of packages reported.
			"page_pattern" : "/html/body//a[regex:test(@href, '^kernel-(devel-)?[0-9].*\.rpm$')]/@href"
		},

		{
			"root" : "http://vault.centos.org/",
			"discovery_pattern" : "//body//table/tr/td/a[regex:test(@href, '^6|7.*$')]/@href",
			"subdirs" : [
				"os/x86_64/Packages/",
				"updates/x86_64/Packages/"
			],
			"page_pattern" : "//body//table/tr/td/a[regex:test(@href, '^kernel-(devel-)?[0-9].*\.rpm$')]/@href"
		},

		{
			"root" : "http://vault.centos.org/centos/",
			"discovery_pattern" : "//body//table/tr/td/a[regex:test(@href, '^6|7.*$')]/@href",
			"subdirs" : [
				"os/x86_64/Packages/",
				"updates/x86_64/Packages/"
			],
			"page_pattern" : "//body//table/tr/td/a[regex:test(@href, '^kernel-(devel-)?[0-9].*\.rpm$')]/@href"
		}
	]
}

#
# In our design you are not supposed to modify the code. The whole script is
# created so that you just have to add entry to the `repos` array and new
# links will be found automagically without needing to write any single line
# of code.
#
packages = {}

if len(sys.argv) < 2 or not sys.argv[1] in repos:
	sys.stderr.write("Usage: " + sys.argv[0] + " <distro>\n")
	sys.exit(1)

#
# Navigate the `repos` tree and look for packages we need that match the
# patterns given. Save the result in `packages`.
#
for repo in repos[sys.argv[1]]:
	
	root = urllib2.urlopen(repo["root"]).read()
	versions = html.fromstring(root).xpath(repo["discovery_pattern"], namespaces = {"regex": "http://exslt.org/regular-expressions"})

	for version in versions:
		for subdir in repo["subdirs"]:

			# The try - except block is used because 404 errors and similar
			# might happen (and actually happen because not all repos have
			# packages we need)
			try:
				source = repo["root"] + version + subdir
				page = urllib2.urlopen(source).read()
				rpms = html.fromstring(page).xpath(repo["page_pattern"], namespaces = {"regex": "http://exslt.org/regular-expressions"})

				for rpm in rpms:
					if not rpm in packages:
						packages[rpm] = source + rpm
			except:
				continue

#
# Print URLs to stdout
#
for rpm, url in packages.iteritems():
	print(url)