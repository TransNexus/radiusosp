#!/bin/sh
#
# logadm_FreeRADIUS.sh
#
# This logadm script for Solaris is used to rotate FreeRADIUS
# radius.log file.  It should be triggered by cron of the user runs
# FreeRADIUS daily.
#
# The FreeRADIUS log directory should be "$RADIUS_PATH/var/log/radius"
# For standard installation, $RADIUS_PATH=/usr/local
#
# "-C 7" to store 7 old log files.
# "-p 1d" to rotate every day or "-p now" since cron run this
#     command every day
# "-z 0" to compress all old log files.
#
/usr/sbin/logadm -C 7 -p now -z 0 $RADIUS_PATH/var/log/radius/radius.log

