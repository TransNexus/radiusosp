#!/bin/bash
# restart_FreeRADIUS.sh
#
# This script checks if FreeRADIUS is running.
# If the application is not running, it restarts it.
#

#
if pgrep radiusd >/dev/null 2>&1
        then
                # Do nothing, the radius server is running
        exit 1
fi
        echo "!!!FreeRADIUS is not running!!!"
        echo "The application will be restarted"

# The 'x' increases debugging ##
#
## SINGLE_PACKAGE mode
# $RADIUS_HOME/sbin/radiusd -fx &
$RADIUS_HOME/sbin/radiusd -f &
#
## FreeRADIUS only mode
# /usr/local/sbin/radiusd -fx &
# /usr/local/sbin/radiusd -f &
