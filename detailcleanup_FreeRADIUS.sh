#!/bin/sh
#
# detailcleanup_FreeRADIUS.sh
#
# This script is used to cleanup FreeRADIUS detail files.  It removes
# the detail files that are not modified more than 15 days.  It should
# be triggered by cron of the user runs FreeRADIUS daily.
#
# The FreeRADIUS log directory should be "$RADIUS_PATH/var/log/radius"
# For standard installation, $RADIUS_PATH=/usr/local
#
find $RADIUS_PATH/var/log/radius/radacct/ -name 'detail-*' -mtime +15 -exec rm -f '{}' \;

