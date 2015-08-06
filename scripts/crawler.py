#!/usr/bin/python

import urllib2
from lxml import etree
from lxml import html
from StringIO import StringIO

repos = {
	"CentOS" : [
		{	# mirrors.kernel.org

			# You are supposed to use XPath syntax in the `pattern` attribute.
			# Fore more information, visit http://lxml.de/xpathxslt.html
			"pattern" : "/html/body//a[regex:test(@href, '^(kernel-headers-).*\.rpm$')]/@href",
			#"pattern" : "/html/body//a[starts-with(text(), 'kernel-headers')]/@href",
			
			# An array of web folders in which look for packages (all links
			# share the same `pattern`)
			"links" : [
				"https://mirrors.kernel.org/centos/7/os/x86_64/Packages/",
				"https://mirrors.kernel.org/centos/7/updates/x86_64/Packages/"
			]
		},

		{	# vault.centos.org
			"pattern" : "//body//table/tr/td/a[regex:test(@href, '^(kernel-headers-).*\.rpm$')]/@href",
			"links" : [
				"http://vault.centos.org/7.0.1406/os/x86_64/Packages/",
				"http://vault.centos.org/7.0.1406/updates/x86_64/Packages/"
			]
		}
	]
}

sources = {}
"""
sources = {
	"distro" : {
		"rpm1" : "http://rpm1",
		"rpm2" : "http://rpm2",
		"rpm3" : "http://rpm3",
	},
	"distro" : {
		"rpm1" : "http://rpm1",
		"rpm2" : "http://rpm2",
		"rpm3" : "http://rpm3",
	},
	...
}
"""

# In our design you are not supposed to modify the code. The whole script is
# created so that you just have to add entry to the `repos` array and new
# links will be found automagically without needing to write any single line
# of code.

#
# Navigate the `repos` tree and look for packages we need that match the
# pattern given. Save the result in `sources`.
#
for name, repo in repos.iteritems():
	for source in repo:
		for link in source["links"]:

			page = urllib2.urlopen(link).read()	# This might rise an exception
			rpms = html.fromstring(page).xpath(source["pattern"], namespaces = {"regex": "http://exslt.org/regular-expressions"})

			for rpm in rpms:
				if not name in sources:
					sources[name] = {}
				if not rpm in sources[name]:
					sources[name][rpm] = link + rpm
#
# Print URLs to stdout
#
for distro, rpms in sources.iteritems():
	for rpm, url in rpms.iteritems():
		print rpm + "\t" + url
