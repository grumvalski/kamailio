#!/bin/bash

BASEDIR=/opt/kamailio
BINDIR=$BASEDIR/sbin
DAEMON=$BINDIR/kamailio
CFGDIR=$BASEDIR/etc/kamailio
RUNDIR=$BASEDIR/var/run
COREDIR=$BASEDIR/core_dir/corefiles
USER=root
GROUP=root
SH_MEM=128
PKG_MEM=64

SERVICE=$1
ACTION=$2

if [ -z "$SERVICE"  ]; then
	echo "unspecified service name"
	exit 1
fi

if [ -z "$ACTION"  ]; then
	echo "unspecified action"
	exit 1
fi

PIDFILE=$RUNDIR/kamailio.$SERVICE.pid
CFGFILE=$CFGDIR/kamailio.$SERVICE.cfg

start() {
		echo "Starting $SERVICE service"
		$DAEMON -P $PIDFILE -f $CFGFILE -w $COREDIR -u $USER -g $GROUP -m $SH_MEM -M $PKG_MEM
}

stop() {
		echo "Stopping $SERVICE service"
		kill `cat $PIDFILE`
}

case "$ACTION" in
	start)
		start
		;;
	stop)
		stop
		;;
	restart)
		stop
		start
		;;
	*)
		echo "Usage: $0 $NAME {start|stop|restart}" >&2
		exit 1
		;;
esac

exit 0

