#!/usr/bin/env python

# Author: Samuele Pilleri
# Date: August 17th, 2015

import bz2
import sqlite3
import sys
import urllib2
import tempfile
from lxml import html

#
# This is the main configuration tree for easily analyze Linux repositories
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
            "discovery_pattern" : "/html/body//pre/a[regex:test(@href, '^6|^7.*$')]/@href",

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
            "discovery_pattern" : "//body//table/tr/td/a[regex:test(@href, '^6|^7.*$')]/@href",
            "subdirs" : [
                "os/x86_64/Packages/",
                "updates/x86_64/Packages/"
            ],
            "page_pattern" : "//body//table/tr/td/a[regex:test(@href, '^kernel-(devel-)?[0-9].*\.rpm$')]/@href"
        },

        {
            "root" : "http://vault.centos.org/centos/",
            "discovery_pattern" : "//body//table/tr/td/a[regex:test(@href, '^6|^7.*$')]/@href",
            "subdirs" : [
                "os/x86_64/Packages/",
                "updates/x86_64/Packages/"
            ],
            "page_pattern" : "//body//table/tr/td/a[regex:test(@href, '^kernel-(devel-)?[0-9].*\.rpm$')]/@href"
        }
    ],

    "Ubuntu" : [
        {
            # Had to split the URL because, unlikely other repos for which the
            # script was first created, Ubuntu puts everything into a single
            # folder. The real URL is be:
            # http://mirrors.us.kernel.org/ubuntu/pool/main/l/linux/
            "root" : "https://mirrors.kernel.org/ubuntu/pool/main/l/",
            "discovery_pattern" : "/html/body//a[@href = 'linux/']/@href",
            "subdirs" : [""],
            "page_pattern" : "/html/body//a[regex:test(@href, '^linux-(image|headers)-[3-9].*-generic.*amd64.deb$')]/@href"
        },

        {
            "root" : "https://mirrors.kernel.org/ubuntu/pool/main/l/",
            "discovery_pattern" : "/html/body//a[@href = 'linux/']/@href",
            "subdirs" : [""],
            "page_pattern" : "/html/body//a[regex:test(@href, '^linux-headers-[3-9].*_all.deb$')]/@href"
        },

        {
            "root" : "http://security.ubuntu.com/ubuntu/pool/main/l/",
            "discovery_pattern" : "/html/body//a[@href = 'linux/']/@href",
            "subdirs" : [""],
            "page_pattern" : "/html/body//a[regex:test(@href, '^linux-(image|headers)-[3-9].*-generic.*amd64.deb$')]/@href"
        },

        {
            "root" : "http://security.ubuntu.com/ubuntu/pool/main/l/",
            "discovery_pattern" : "/html/body//a[@href = 'linux/']/@href",
            "subdirs" : [""],
            "page_pattern" : "/html/body//a[regex:test(@href, '^linux-headers-[3-9].*_all.deb$')]/@href"
        }
    ],

    "Fedora" : [
        {
            "root" : "https://mirrors.kernel.org/fedora/releases/",
            "discovery_pattern": "/html/body//a[regex:test(@href, '^2[2-9]/$')]/@href",
            "subdirs" : [
                "Everything/x86_64/os/Packages/k/"
            ],
            "page_pattern" : "/html/body//a[regex:test(@href, '^kernel-(core|devel)-[0-9].*\.rpm$')]/@href"
        },

        {
            "root" : "https://mirrors.kernel.org/fedora/updates/",
            "discovery_pattern": "/html/body//a[regex:test(@href, '^2[2-9]/$')]/@href",
            "subdirs" : [
                "x86_64/k/"
            ],
            "page_pattern" : "/html/body//a[regex:test(@href, '^kernel-(core|devel)-[0-9].*\.rpm$')]/@href"
        },

        # {
        # 	"root" : "https://mirrors.kernel.org/fedora/development/",
        # 	"discovery_pattern": "/html/body//a[regex:test(@href, '^2[2-9]/$')]/@href",
        # 	"subdirs" : [
        # 		"x86_64/os/Packages/k/"
        # 	],
        # 	"page_pattern" : "/html/body//a[regex:test(@href, '^kernel-(core|devel)-[0-9].*\.rpm$')]/@href"
        # }
    ],

    "CoreOS" : [
        # {
        #     "root" : "http://alpha.release.core-os.net/",
        #     "discovery_pattern": "/html/body//a[regex:test(@href, 'amd64-usr')]/@href",
        #     "subdirs" : [
        #         ""
        #     ],
        #     "page_pattern" : "/html/body//a[regex:test(@href, '^[5-9][0-9][0-9]|current|[1][0-9]{3}')]/@href"
        # },

        {
            "root" : "http://beta.release.core-os.net/",
            "discovery_pattern": "/html/body//a[regex:test(@href, 'amd64-usr')]/@href",
            "subdirs" : [
                ""
            ],
            "page_pattern" : "/html/body//a[regex:test(@href, '^[5-9][0-9][0-9]|current|[1][0-9]{3}')]/@href"
        },

        {
            "root" : "http://stable.release.core-os.net/",
            "discovery_pattern": "/html/body//a[regex:test(@href, 'amd64-usr')]/@href",
            "subdirs" : [
                ""
            ],
            "page_pattern" : "/html/body//a[regex:test(@href, '^[4-9][0-9][0-9]|current|[1][0-9]{3}')]/@href"
        }
    ],

    "Debian": [
        {
            "root": "https://mirrors.kernel.org/debian/pool/main/l/",
            "discovery_pattern": "/html/body/pre/a[@href = 'linux/']/@href",
            "subdirs": [""],
            "page_pattern": "/html/body//a[regex:test(@href, '^linux-(image|headers)-[3-9]\.[0-9]+\.[0-9]+.*amd64.deb$')]/@href",
            "exclude_patterns": ["-rt", "dbg", "trunk", "all", "exp", "unsigned"]
        },
        {
            "root": "http://security.debian.org/pool/updates/main/l/",
            "discovery_pattern": "/html/body/table//tr/td/a[@href = 'linux/']/@href",
            "subdirs": [""],
            "page_pattern": "/html/body//a[regex:test(@href, '^linux-(image|headers)-[3-9]\.[0-9]+\.[0-9]+.*amd64.deb$')]/@href",
            "exclude_patterns": ["-rt", "dbg", "trunk", "all", "exp", "unsigned"]
        },
        {
            "root": "http://mirrors.kernel.org/debian/pool/main/l/",
            "discovery_pattern": "/html/body/pre/a[@href = 'linux-tools/']/@href",
            "subdirs": [""],
            "page_pattern": "/html/body//a[regex:test(@href, '^linux-kbuild-.*amd64.deb$')]/@href",
            "exclude_patterns": ["-rt", "dbg", "trunk", "all", "exp", "unsigned"]
        }
    ],

    "AmazonLinux": [
        {
            "root": "http://repo.us-east-1.amazonaws.com/latest/updates/mirror.list",
            "discovery_pattern": "SELECT * FROM packages WHERE name LIKE 'kernel%'",
            "subdirs": [""],
            "page_pattern": "",
            "exclude_patterns": ["doc","tools","headers"]
        },
        {
            "root": "http://repo.us-east-1.amazonaws.com/latest/main/mirror.list",
            "discovery_pattern": "SELECT * FROM packages WHERE name LIKE 'kernel%'",
            "subdirs": [""],
            "page_pattern": "",
            "exclude_patterns": ["doc","tools","headers"]
        },
        {
            "root": "http://repo.us-east-1.amazonaws.com/_placeholder_/updates/mirror.list",
            "discovery_pattern": "SELECT * FROM packages WHERE name LIKE 'kernel%'",
            "subdirs": [""],
            "page_pattern": "",
            "exclude_patterns": ["doc","tools","headers"]
        },
        {
            "root": "http://repo.us-east-1.amazonaws.com/_placeholder_/main/mirror.list",
            "discovery_pattern": "SELECT * FROM packages WHERE name LIKE 'kernel%'",
            "subdirs": [""],
            "page_pattern": "",
            "exclude_patterns": ["doc","tools","headers"]
        }
    ]
}

def exclude_patterns(repo, packages, base_url, urls):
    for rpm in packages:
        if "exclude_patterns" in repo and any(x in rpm for x in repo["exclude_patterns"]):
            continue
        else:
            urls.add(base_url + str(urllib2.unquote(rpm)))

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

distro = sys.argv[1]

#
# Navigate the `repos` tree and look for packages we need that match the
# patterns given. Save the result in `packages`.
#
for index, repo in enumerate(repos[distro]):
    if distro == 'AmazonLinux':
        try:
            if "_placeholder_" in repo["root"]:
                repo["root"] = repo["root"].replace("_placeholder_", releasever)
            # Look for the first mirror that works
            for line in urllib2.urlopen(repo["root"]).readlines():
                base_mirror_url = line.replace('$basearch','x86_64').replace('\n','') + '/'

                # Building previous releasever on first loop only
                if index == 0:
                    # This is all to handle the non-latest release version consistently
                    repo_date = line.split('/')[3].split('.')
                    # Check month of release
                    if repo_date[1] == "03":
                        previous_year = str(int(repo_date[0]) - 1)
                        prior_release = [previous_year, "09"]
                        releasever = ".".join(prior_release)
                    else:
                        prior_release = [repo_date[0], "03"]
                        releasever = ".".join(prior_release)
                try:
                    response = urllib2.urlopen(base_mirror_url + 'repodata/primary.sqlite.bz2')
                except:
                    continue

                break
        except:
            continue

        decompressed_data = bz2.decompress(response.read())
        db_file = tempfile.NamedTemporaryFile()
        db_file.write(decompressed_data)
        conn = sqlite3.connect(db_file.name)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        rpms = [r["location_href"] for r in c.execute(repo["discovery_pattern"])]
        exclude_patterns(repo, rpms, base_mirror_url, urls)
        conn.close()
        db_file.close()
    else:
        try:
            root = urllib2.urlopen(repo["root"],timeout=URL_TIMEOUT).read()
        except:
            continue

        versions = html.fromstring(root).xpath(repo["discovery_pattern"], namespaces = {"regex": "http://exslt.org/regular-expressions"})
        for version in versions:
            for subdir in repo["subdirs"]:
                # The try - except block is used because 404 errors and similar
                # might happen (and actually happen because not all repos have
                # packages we need)
                try:
                    source = repo["root"] + version + subdir
                    page = urllib2.urlopen(source,timeout=URL_TIMEOUT).read()
                    rpms = html.fromstring(page).xpath(repo["page_pattern"], namespaces = {"regex": "http://exslt.org/regular-expressions"})
                    exclude_patterns(repo, rpms, source, urls)
                except:
                    continue

#
# Print URLs to stdout
#
for url in urls:
    print(url)
