#!/bin/sh
#
# detailcleanup_FreeRADIUS.sh
#
# This script is used to cleanup FreeRADIUS detail files.  It removes the 
# detail files that are not modified more than 15 days.  It should be triggered
# by cron of root daily.
#
# The FreeRADIUS log directory should be "$RADIUS_HOME/var/log/radius".
#
## SINGLE_PACKAGE mode
find $RADIUS_HOME/var/log/radius/radacct/ -name 'detail-????????:??' -mmin +180 -exec gzip -f '{}' \;
find $RADIUS_HOME/var/log/radius/radacct/ -name 'detail-*' -mtime +15 -exec rm -f '{}' \;
#
## FreeRADIUS only mode
# find /usr/local/var/log/radius/radacct/ -name 'detail-????????:??' -mmin +180 -exec gzip -f '{}' \;
# find /usr/local/var/log/radius/radacct/ -name 'detail-*' -mtime +15 -exec rm -f '{}' \;
