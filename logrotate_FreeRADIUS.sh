#!/bin/sh
#
# logrotate_FreeRADIUS.sh
#
# This logrotate script for Linux is used to rotate FreeRADIUS
# radius.log file.  It should be triggered by cron of the user runs
# FreeRADIUS daily.
#
# The FreeRADIUS log directory should be "$RADIUS_PATH/var/log/radius"
# For standard installation, $RADIUS_PATH=/usr/local
#
# logrotate_FreeRADIUS.sh       logrotate script file
# logrotate_FreeRADIUS.cfg      logrotate configuration file
# logrotate_FreeRADIUS.status   logrotate outupt status file
#
# All files should be under $RADIUS_UTILS, which must be defined.
#
/usr/sbin/logrotate -s $RADIUS_UTILS/logrotate_FreeRADIUS.status $RADIUS_UTILS/logrotate_FreeRADIUS.cfg

