#!/usr/bin/python
import sys
import urllib2
import json
import re

URL_TIMEOUT=30
LINUXKIT_KERNEL_IMAGE = "linuxkit/kernel"
HUB_URL_TEMPLATE = "https://registry.hub.docker.com/v1/repositories/%s/tags"
TAG_REGEX = re.compile("\d+\.\d+\.\d+-[a-z0-9][a-z0-9]+")
all_tags_s = urllib2.urlopen(HUB_URL_TEMPLATE % LINUXKIT_KERNEL_IMAGE, timeout=URL_TIMEOUT).read()

for tag in json.loads(all_tags_s):
    if re.match(TAG_REGEX, tag["name"]):
        print("%s:%s" % (LINUXKIT_KERNEL_IMAGE, tag["name"]))