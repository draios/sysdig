#!/usr/bin/python

# Author: Samuele Pilleri
# Date: August 6th, 2015

#
# This is the entrypoint of the new Python probe builder.
#
# If you want to add a repository, modify the `repos` variable in the
# `Crawler.py` script
#

from Crawler import crawl

print "Starting deep crawling..."

packages = crawl()

total = 0
for distro, rpms in packages.iteritems():
	total += len(rpms)

print "Found " + str(total) + " rpms..."

"""
for name, package in packages.iteritems():
	print name
	for key, value in package.iteritems():
		print key + "\t" + value
"""