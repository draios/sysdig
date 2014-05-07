#!/bin/bash
set -exu

SCRIPT=$(readlink -f $0)
BASEDIR=$(dirname $SCRIPT)

SYSDIG=~/build/sysdig/build/debug/userspace/sysdig/sysdig
CHISELS=~/build/sysdig/build/debug/userspace/sysdig/chisels/
TRACEDIR=~/src/tracesgb2
BASELINEDIR=.
RESULTDIR=.

# $BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-p*%fd.num %fd.type %fd.typechar %fd.name %fd.directory %fd.ip %fd.cip %fd.sip %fd.port %fd.cport %fd.sport %fd.l4proto %fd.sockfamily %fd.is_server" $TRACEDIR $RESULTDIR/fd_fields_new $BASELINEDIR/fd_fields
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-p%thread.exectime" $TRACEDIR $RESULTDIR/exetime_new $BASELINEDIR/exetime
# Category: CPU Usage
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-ctopprocs_cpu" $TRACEDIR $RESULTDIR/topprocs_cpu_new $BASELINEDIR/topprocs_cpu
# Category: I/O
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-cecho_fds" $TRACEDIR $RESULTDIR/echo_fds_new $BASELINEDIR/echo_fds
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-cfdbytes_by" $TRACEDIR $RESULTDIR/fdbytes_by_new $BASELINEDIR/fdbytes_by
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-cfdcount_by" $TRACEDIR $RESULTDIR/fdcount_by_new $BASELINEDIR/fdcount_by
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-ciobytes" $TRACEDIR $RESULTDIR/iobytes_new $BASELINEDIR/iobytes
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-ciobytes_file" $TRACEDIR $RESULTDIR/iobytes_file_new $BASELINEDIR/iobytes_file
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-cstderr" $TRACEDIR $RESULTDIR/stderr_new $BASELINEDIR/stderr
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-cstdin" $TRACEDIR $RESULTDIR/stdin_new $BASELINEDIR/stdin
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-cstdout" $TRACEDIR $RESULTDIR/stdout_new $BASELINEDIR/stdout
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-ctopfiles_bytes" $TRACEDIR $RESULTDIR/topfiles_bytes_new $BASELINEDIR/topfiles_bytes
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-ctopfiles_time" $TRACEDIR $RESULTDIR/topfiles_time_new $BASELINEDIR/topfiles_time
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-ctopprocs_file" $TRACEDIR $RESULTDIR/topprocs_file_new $BASELINEDIR/topprocs_file
# Category: Net
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-ciobytes_net" $TRACEDIR $RESULTDIR/iobytes_net_new $BASELINEDIR/iobytes_net
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-cspy_ip" $TRACEDIR $RESULTDIR/spy_ip_new $BASELINEDIR/spy_ip
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-cspy_port" $TRACEDIR $RESULTDIR/_new $BASELINEDIR/spy_port
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-ctopconns" $TRACEDIR $RESULTDIR/topconns_new $BASELINEDIR/topconns
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-ctopports_server" $TRACEDIR $RESULTDIR/topports_server_new $BASELINEDIR/topports_server
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-ctopprocs_net" $TRACEDIR $RESULTDIR/topprocs_net_new $BASELINEDIR/topprocs_net
# Category: Performance
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-cbottlenecks" $TRACEDIR $RESULTDIR/bottlenecks_new $BASELINEDIR/bottlenecks
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-cfileslower" $TRACEDIR $RESULTDIR/fileslower_new $BASELINEDIR/fileslower
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-cproc_exec_time" $TRACEDIR $RESULTDIR/proc_exec_time_new $BASELINEDIR/proc_exec_time
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-cscallslower" $TRACEDIR $RESULTDIR/scallslower_new $BASELINEDIR/scallslower
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-ctopscalls" $TRACEDIR $RESULTDIR/topscalls_new $BASELINEDIR/topscalls
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-ctopscalls_time" $TRACEDIR $RESULTDIR/topscalls_time_new $BASELINEDIR/topscalls_time
# Category: Security
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-cspy_users" $TRACEDIR $RESULTDIR/spy_users_new $BASELINEDIR/spy_users
# Category: Errors
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-ctopfiles_errors" $TRACEDIR $RESULTDIR/topfiles_errors_new $BASELINEDIR/topfiles_errors
$BASEDIR/sysdig_batch_parser.sh $SYSDIG $CHISELS "-ctopprocs_errors" $TRACEDIR $RESULTDIR/topprocs_errors_new $BASELINEDIR/topprocs_errors
