#!/bin/bash
#set -e

/usr/bin/sysdig-probe-installer

exec "$@"
