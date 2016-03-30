#!/usr/bin/python

import sys
import json
import urllib2
from lxml import html

#
# This script is used to crawl given repos hunting for packages. It doesn't
# handle duplicates (this is done by the aggregator).
# It produces a JSON containing an array of links for each distro.
#

#
# This is the main configuration tree for easily analyze Linux repositories
# hunting packages. When adding repos or so be sure to respect the same data
# structure.
# Each distro is seen as a tree. There can be multiple roots because there can
# be different sources for packages.
# Each node can have the following fields:
#  - `prefix` : this is a string that contains a fixed path to be added to the
#               string before crawling for new results
#  - `query`  : a mixed XPath and Regex query for matching HTML nodes and
#               attributes
#  - `next`   : an array of subnodes or None in case of leaf. It is optional.
#  - `exclude`: an array of strings that must not be present in crawled string.
#               It's useful for simplifying the query.
#
repos = {
	"CentOS" : [
		{
			"prefix" : "http://mirrors.kernel.org/centos/",
			"query" : "/html/body//pre/a[regex:test(@href, '^(6|7){1}.*$')]/@href",
			"next" : [
				{
					"prefix" : "os/x86_64/Packages/",
					"query" : "/html/body//a[regex:test(@href, '^kernel-(devel-)?[0-9].*\.rpm$')]/@href",
					"next" : None
				},
				{
					"prefix" : "updates/x86_64/Packages/",
					"query" : "/html/body//a[regex:test(@href, '^kernel-(devel-)?[0-9].*\.rpm$')]/@href",
					"next" : None
				}
			]
		},

		{
			"prefix" : "http://vault.centos.org/",
			"query" : "//body//table/tr/td/a[regex:test(@href, '^(6|7){1}.*$')]/@href",
			"next" : [
				{
					"prefix" : "os/x86_64/Packages/",
					"query" : "//body//table/tr/td/a[regex:test(@href, '^kernel-(devel-)?[0-9].*\.rpm$')]/@href",
					"next" : None
				},

				{
					"prefix" : "updates/x86_64/Packages/",
					"query" : "//body//table/tr/td/a[regex:test(@href, '^kernel-(devel-)?[0-9].*\.rpm$')]/@href",
					"next" : None
				}
			]
		},

		{
			"prefix" : "http://vault.centos.org/centos/",
			"query" : "//body//table/tr/td/a[regex:test(@href, '^6|7.*$')]/@href",
			"next" : [
				{
					"prefix" : "os/x86_64/Packages/",
					"query" : "//body//table/tr/td/a[regex:test(@href, '^kernel-(devel-)?[0-9].*\.rpm$')]/@href",
					"next" : None
				},

				{
					"prefix" : "updates/x86_64/Packages/",
					"query" : "//body//table/tr/td/a[regex:test(@href, '^kernel-(devel-)?[0-9].*\.rpm$')]/@href",
					"next" : None
				}
			]
		}
	],

	"Ubuntu" : [
		{
			"prefix" : "http://mirrors.us.kernel.org/ubuntu/pool/main/l/linux/",
			"query" : "/html/body//a[regex:test(@href, '^linux-(image|headers)-[3-9].*-generic.*amd64.deb$')]/@href",
			"next" : None
		},

		{
			"prefix" : "https://mirrors.kernel.org/ubuntu/pool/main/l/linux/",
			"query" : "/html/body//a[regex:test(@href, '^linux-headers-[3-9].*_all.deb$')]/@href",
			"next" : None
		},

		{
			"prefix" : "http://security.ubuntu.com/ubuntu/pool/main/l/linux/",
			"query" : "/html/body//a[regex:test(@href, '^linux-(image|headers)-[3-9].*-generic.*amd64.deb$')]/@href",
			"next" : None
		},

		{
			"prefix" : "http://security.ubuntu.com/ubuntu/pool/main/l/linux/",
			"query" : "/html/body//a[regex:test(@href, '^linux-headers-[3-9].*_all.deb$')]/@href",
			"next" : None
		}
	],

	"Fedora" : [
		{
			"prefix" : "https://mirrors.kernel.org/fedora/releases/",
			"query" : "/html/body//a[regex:test(@href, '^2[2-9]/$')]/@href",
			"next" : [
				{
					"prefix" : "Everything/x86_64/os/Packages/k/",
					"query" : "/html/body//a[regex:test(@href, '^kernel-(core|devel)-[0-9].*\.rpm$')]/@href",
					"next" : None
				}
			]
		},

		{
			"prefix" : "https://mirrors.kernel.org/fedora/updates/",
			"query" : "/html/body//a[regex:test(@href, '^2[2-9]/$')]/@href",
			"next" : [
				{
					"prefix" : "x86_64/k/",
					"query" : "/html/body//a[regex:test(@href, '^kernel-(core|devel)-[0-9].*\.rpm$')]/@href",
					"next" : None
				}
			]
		}
	],

	"CoreOS" : [
		{
			"prefix" : "http://alpha.release.core-os.net/amd64-usr/",
			"query" : "/html/body//a[regex:test(@href, '^[0-9]+|current')]/@href",
			"next" : [
				{
					"prefix" : "",
					"query" : "/html/body/a[regex:test(@href, '^coreos_developer_container\.bin\.bz2$')]/@href",
					"next" : None
				}
			]
		},

		{
			"prefix" : "http://beta.release.core-os.net/amd64-usr/",
			"query" : "/html/body//a[regex:test(@href, '^[0-9]+|current')]/@href",
			"next" : [
				{
					"prefix" : "",
					"query" : "/html/body/a[regex:test(@href, '^coreos_developer_container\.bin\.bz2$')]/@href",
					"next" : None
				}
			]
		},

		{
			"prefix" : "http://stable.release.core-os.net/amd64-usr/",
			"query" : "/html/body//a[regex:test(@href, '^[0-9]+|current')]/@href",
			"next" : [
				{
					"prefix" : "",
					"query" : "/html/body/a[regex:test(@href, '^coreos_developer_container\.bin\.bz2$')]/@href",
					"next" : None
				}
			]
		}
	],

	"Debian" : [
		{
			"prefix" : "https://mirrors.kernel.org/debian/pool/main/l/linux/",
			"query" : "/html/body//a[regex:test(@href, '^linux-(image|headers)-[3-9]\.[0-9]+\.[0-9]+.*amd64.deb$')]/@href",
			"exclude" : ["-rt", "dbg", "trunk", "all", "exp"],
			"next" : None
		},

		{
			"prefix" : "http://security.debian.org/pool/updates/main/l/linux/",
			"query" : "/html/body//a[regex:test(@href, '^linux-(image|headers)-[3-9]\.[0-9]\.[0-9]+.*amd64.deb$')]/@href",
			"exclude" : ["-rt", "dbg", "trunk", "all", "exp"],
			"next" : None
		},

		{
			"prefix" : "http://mirrors.kernel.org/debian/pool/main/l/linux-tools/",
			"query" : "/html/body//a[regex:test(@href, '^linux-kbuild-.*amd64.deb$')]/@href",
			"exclude" : ["-rt", "dbg", "trunk", "all", "exp"],
			"next" : None
		}
	]
}

#
# In our design you are not supposed to modify the code. The whole script is
# created so that you just have to add entry to the `repos` array and new
# links will be found automagically without needing to write any single line of
# code.
#

urls = {}

def crawl(tree, given = ""):
	ret = []
	for node in tree:
		try:
			page = urllib2.urlopen(given + node["prefix"]).read()
			results = html.fromstring(page).xpath(node["query"], namespaces = {"regex": "http://exslt.org/regular-expressions"})

			for result in results:
				if "next" in node and not node["next"] == None:
					ret += crawl(node["next"], given + node["prefix"] + result)
				else:
					if "exclude" in node and any(x in result for x in node["exclude"]):
						continue
					else:
						ret.append(given + node["prefix"] + str(urllib2.unquote(result)))

		except:
			continue
	return ret

for os, info in repos.iteritems():
	urls[os] = crawl(info)

print(json.dumps(urls))
