#!/bin/bash
set -exu

SCRIPT=$(readlink -f $0)
BASEDIR=$(dirname $SCRIPT)

SYSDIG=$1
CHISELS=$2
TMPBASE=${3:-$(mktemp -d --tmpdir sysdig.XXXXXXXXXX)}
TRACEDIR="${TMPBASE}/traces"
RESULTDIR="${TMPBASE}/results"
BASELINEDIR="${TMPBASE}/baseline"

if [ ! -d "$TRACEDIR" ]; then
	mkdir -p $TRACEDIR
	cd $TRACEDIR
	wget https://s3.amazonaws.com/download.draios.com/sysdig-tests/traces.zip
	unzip traces.zip
	rm -rf traces.zip
	cd -
fi

if [ ! -d "$BASELINEDIR" ]; then
	mkdir -p $BASELINEDIR
	cd $BASELINEDIR
	wget https://s3.amazonaws.com/download.draios.com/sysdig-tests/baseline.zip
	unzip baseline.zip
	rm -rf baseline.zip
	cd -
fi

echo "Executing sysdig tests in ${TMPBASE}"

# Fields
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-p\"*%fd.num %fd.type %fd.typechar %fd.name %fd.directory %fd.filename %fd.cip %fd.sip %fd.cport %fd.sport %fd.l4proto %fd.sockfamily %fd.is_server\"" $TRACEDIR $RESULTDIR/fd_fields $BASELINEDIR/fd_fields
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-p%thread.exectime" $TRACEDIR $RESULTDIR/exetime $BASELINEDIR/exetime
# Category: CPU Usage
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-ctopprocs_cpu" $TRACEDIR $RESULTDIR/topprocs_cpu $BASELINEDIR/topprocs_cpu
# Category: I/O
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-cecho_fds" $TRACEDIR $RESULTDIR/echo_fds $BASELINEDIR/echo_fds
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-cfdbytes_by fd.name" $TRACEDIR $RESULTDIR/fdbytes_by $BASELINEDIR/fdbytes_by
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-cfdcount_by fd.name" $TRACEDIR $RESULTDIR/fdcount_by $BASELINEDIR/fdcount_by
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-ciobytes" $TRACEDIR $RESULTDIR/iobytes $BASELINEDIR/iobytes
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-ciobytes_file" $TRACEDIR $RESULTDIR/iobytes_file $BASELINEDIR/iobytes_file
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-cstderr" $TRACEDIR $RESULTDIR/stderr $BASELINEDIR/stderr
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-cstdin" $TRACEDIR $RESULTDIR/stdin $BASELINEDIR/stdin
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-cstdout" $TRACEDIR $RESULTDIR/stdout $BASELINEDIR/stdout
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-ctopfiles_bytes" $TRACEDIR $RESULTDIR/topfiles_bytes $BASELINEDIR/topfiles_bytes
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-ctopfiles_time" $TRACEDIR $RESULTDIR/topfiles_time $BASELINEDIR/topfiles_time
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-ctopprocs_file" $TRACEDIR $RESULTDIR/topprocs_file $BASELINEDIR/topprocs_file
# Category: Net
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-ciobytes_net" $TRACEDIR $RESULTDIR/iobytes_net $BASELINEDIR/iobytes_net
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-cspy_ip 127.0.0.1" $TRACEDIR $RESULTDIR/spy_ip $BASELINEDIR/spy_ip
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-cspy_port 80" $TRACEDIR $RESULTDIR/spy_port $BASELINEDIR/spy_port
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-ctopconns" $TRACEDIR $RESULTDIR/topconns $BASELINEDIR/topconns
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-ctopports_server" $TRACEDIR $RESULTDIR/topports_server $BASELINEDIR/topports_server
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-ctopprocs_net" $TRACEDIR $RESULTDIR/topprocs_net $BASELINEDIR/topprocs_net
# Category: Performance
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-cbottlenecks" $TRACEDIR $RESULTDIR/bottlenecks $BASELINEDIR/bottlenecks
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-cfileslower 1000" $TRACEDIR $RESULTDIR/fileslower $BASELINEDIR/fileslower
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-cnetlower 10" $TRACEDIR $RESULTDIR/netlower $BASELINEDIR/netlower
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-cproc_exec_time" $TRACEDIR $RESULTDIR/proc_exec_time $BASELINEDIR/proc_exec_time
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-cscallslower 1000" $TRACEDIR $RESULTDIR/scallslower $BASELINEDIR/scallslower
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-ctopscalls" $TRACEDIR $RESULTDIR/topscalls $BASELINEDIR/topscalls
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-ctopscalls_time" $TRACEDIR $RESULTDIR/topscalls_time $BASELINEDIR/topscalls_time
# Category: Security
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-cspy_users" $TRACEDIR $RESULTDIR/spy_users $BASELINEDIR/spy_users
# Category: Errors
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-ctopfiles_errors" $TRACEDIR $RESULTDIR/topfiles_errors $BASELINEDIR/topfiles_errors
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-ctopprocs_errors" $TRACEDIR $RESULTDIR/topprocs_errors $BASELINEDIR/topprocs_errors
# JSON
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-j -n 10000" $TRACEDIR $RESULTDIR/fd_fields_json $BASELINEDIR/fd_fields_json

rm -rf "${TMPBASE}"
