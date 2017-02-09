#!/usr/bin/python

import sys
import urllib2
from lxml import html

#
# Copied from kernel-crawler.py and hacked up for oracle linux
# because they don't use a normal directory structure.
#
repos = {
    # Oracle only puts full isos with unhelpful names on mirrors.kernel.org, so skip it
    "OL6-UEK": [
        {
            # yum.oracle.com has a bad cert, so use http instead of https
            "root": "http://yum.oracle.com/",
            "discovery_pattern": "/html/body//h3/a[regex:test(@href, 'oracle-linux-6\.html')]/@href",
            "sub_discovery_pattern": "/html/body//h3[regex:test(., '^UEK Release [3-9]:')]/a[regex:test(@href, 'x86_64/index.html')]/@href",
            "page_pattern": "/html/body//a[regex:test(@href, '^getPackage/kernel-uek-(devel-)?[0-9].*\.rpm$')]/@href",
        }
    ],

    "OL7-UEK": [
        {
            "root": "http://yum.oracle.com/",
            "discovery_pattern": "/html/body//h3/a[regex:test(@href, 'oracle-linux-7\.html')]/@href",
            "sub_discovery_pattern": "/html/body//h3[regex:test(., '^UEK Release [3-9]:')]/a[regex:test(@href, 'x86_64/index.html')]/@href",
            "page_pattern": "/html/body//a[regex:test(@href, '^getPackage/kernel-uek-(devel-)?[0-9].*\.rpm$')]/@href",
        }
    ],

    "Oracle-RHCK": [
        {
            "root": "http://yum.oracle.com/",
            "discovery_pattern": "/html/body//h3/a[regex:test(@href, 'oracle-linux-[6-7]+\.html')]/@href",
            "sub_discovery_pattern": "/html/body//h3[regex:test(., '^Latest:')]/a[regex:test(@href, 'x86_64/index.html')]/@href",
            "page_pattern": "/html/body//a[regex:test(@href, '^getPackage/kernel-(devel-)?[0-9].*\.rpm$')]/@href",
        }
    ]
}

#
# In our design you are not supposed to modify the code. The whole script is
# created so that you just have to add entry to the `repos` array and new
# links will be found automagically without needing to write any single line of
# code.
#
urls = set()
URL_TIMEOUT=30

if len(sys.argv) < 2 or not sys.argv[1] in repos:
    sys.stderr.write("Usage: " + sys.argv[0] + " <distro>\n")
    sys.exit(1)

#
# Navigate the `repos` tree and look for packages we need that match the
# patterns given. Save the result in `packages`.
#
for repo in repos[sys.argv[1]]:
    try:
        root = urllib2.urlopen(repo["root"],timeout=URL_TIMEOUT).read()
    except:
        continue
    versions = html.fromstring(root).xpath(repo["discovery_pattern"], namespaces = {"regex": "http://exslt.org/regular-expressions"})
    for version in versions:
        ver_url = repo["root"] + version
        try:
            subroot = urllib2.urlopen(ver_url,timeout=URL_TIMEOUT).read()
        except:
            continue
        sub_vers = html.fromstring(subroot).xpath(repo["sub_discovery_pattern"], namespaces = {"regex": "http://exslt.org/regular-expressions"})
        for sub_ver in sub_vers:
            sub_ver = sub_ver.lstrip('/')
            # The try - except block is used because 404 errors and similar
            # might happen (and actually happen because not all repos have
            # packages we need)
            try:
                source = repo["root"] + sub_ver
                page = urllib2.urlopen(source,timeout=URL_TIMEOUT).read()
                rpms = html.fromstring(page).xpath(repo["page_pattern"], namespaces = {"regex": "http://exslt.org/regular-expressions"})

                source = source.replace("index.html", "")
                for rpm in rpms:
                    urls.add(source + str(urllib2.unquote(rpm)))
            except:
                continue

#
# Print URLs to stdout
#
for url in urls:
    print(url)
