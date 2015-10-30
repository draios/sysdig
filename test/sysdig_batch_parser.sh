#!/bin/bash
#
# This script runs sysdig on all the trace files (i.e. all the files with scap 
# extension) in the current directory, and compares the result with the one of 
# a previous run.
#
# Arguments:
#  - sysdig path
#  - sysdig chisels directory
#  - sysdig command line
#  - traces directory
#  - prefix of the result directory (it will be completed with the current 
#    date/time)
#  - directory to use as a reference
#
# Examples:
#  ./sysdig_batch_parser.sh "-p%thread.exectime" exetime exetime_2014-04-28_10-18-30
#  ./sysdig_batch_parser.sh "-ctopconns" topconns topconns_2014-04-28_02-51-34 
#
# Note: 
#  if the comparison succeeds, the result directory is deleted. Otherwise, it's 
#  kept there for reference/analysis.
#
set -eu

SYSDIG=$1
SYSDIG_CHISEL_DIR=$2
ARGS=$3
TRACESDIR=$4
DIRNAME=$5
REFERENCEDIR=$6

export SYSDIG_CHISEL_DIR

rm -rf $DIRNAME || true
mkdir -p $DIRNAME

for f in $TRACESDIR/*
do
	echo "Processing $f"
	TZ=UTC eval $SYSDIG -N -r $f $ARGS > $DIRNAME/$(basename $f).output
done

echo Data saved in $DIRNAME

diff -r $DIRNAME $REFERENCEDIR
rm -rf $DIRNAME
