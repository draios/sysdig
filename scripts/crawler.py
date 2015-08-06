#!/usr/bin/python

import urllib2
from lxml import etree
from lxml import html
from StringIO import StringIO

repos = {
	"CentOS" : [
		{	# source 1
			"root" : "https://mirrors.kernel.org/centos/",
			"discovery_pattern" : "/html/body//pre/a[regex:test(@href, '^7.*$')]/@href",
			"subdirs" : [
				"os/x86_64/Packages/",
				"updates/x86_64/Packages/"
			],
			"page_pattern" : "/html/body//a[regex:test(@href, '^(kernel-headers-).*\.rpm$')]/@href"
		},

		{
			"root" : "http://vault.centos.org/",
			"discovery_pattern" : "//body//table/tr/td/a[regex:test(@href, '^7.*$')]/@href",
			"subdirs" : [
				"os/x86_64/Packages/",
				"updates/x86_64/Packages/"
			],
			"page_pattern" : "//body//table/tr/td/a[regex:test(@href, '^(kernel-headers-).*\.rpm$')]/@href"
		}
	]
}

packages = {}

for distro, repositories in repos.iteritems():
	for repo in repositories:
		
		root = urllib2.urlopen(repo["root"]).read()
		versions = html.fromstring(root).xpath(repo["discovery_pattern"], namespaces = {"regex": "http://exslt.org/regular-expressions"})

		for version in versions:
			for subdir in repo["subdirs"]:

				try:
					source = repo["root"] + version + subdir
					page = urllib2.urlopen(source).read()
					rpms = html.fromstring(page).xpath(repo["page_pattern"], namespaces = {"regex": "http://exslt.org/regular-expressions"})

					for rpm in rpms:
						if not distro in packages:
							packages[distro] = {}
						if not rpm in packages[distro]:
							packages[distro][rpm] = source + rpm
				except:	# we don't care about 404s and so
					continue

for name, package in packages.iteritems():
	print name
	for key, value in package.iteritems():
		print key + "\t" + value