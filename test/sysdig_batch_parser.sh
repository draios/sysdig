#
# This script runs sysdig on all the trace files (i.e. all the files with scap 
# extension) in the current directory, and compares the result with the one of 
# a previous run.
#
# Arguments:
#  - sysdig command line
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
platform='windows'
unamestr=`uname`
if [[ "$unamestr" == 'Linux' ]]; then
   platform='linux'
fi

ARGS=$1
if [[ $platform == 'linux' ]]; then
SYSDIGDIR=~/sysdig/build/userspace/sysdig
SYSDIG=$SYSDIGDIR/sysdig
else
SYSDIGDIR=c:/sysdig/build/Release
SYSDIG=$SYSDIGDIR/sysdig.exe
fi

DIRNAME=$2_$(date +%F_%H-%M-%S)
REFERENCEDIR=$3
SYSDIG_CHISEL_DIR=$SYSDIGDIR/chisels
export SYSDIG_CHISEL_DIR

mkdir $DIRNAME

for f in *.scap
do 
 echo "Processing $f"
 #echo "$SYSDIG -r $f $ARGS > $DIRNAME/$f.output"
 $SYSDIG -r $f "$ARGS" > $DIRNAME/$f.output
 RETVAL=$?
 [ $RETVAL -eq 0 ] && echo Success
 [ $RETVAL -ne 0 ] && echo Failure && rm -f $DIRNAME/$f.output && rm -f $DIRNAME/$f.log
done

echo ciao
echo Data saved in $DIRNAME

echo
echo Comparing
diff -r --brief $DIRNAME $REFERENCEDIR
RETVAL=$?
[ $RETVAL -eq 0 ] && echo No change && rm -fr $DIRNAME
[ $RETVAL -ne 0 ] && echo Different!
