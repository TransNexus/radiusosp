#!/bin/bash
#
# restart_FreeRADIUS.sh
#
# This script checks if FreeRADIUS is running.  If the application is
# not running, it restarts it.
#
# The FreeRADIUS directory should be "$RADIUS_PATH". For standard
# installation, $RADIUS_PATH=/usr/local
#

if pgrep radiusd >/dev/null 2>&1
    then
    # Do nothing, the radius server is running
    echo "FreeRADIUS is running."
else
    echo "FreeRADIUS is not running!"
    echo "The application will be restarted"
    $RADIUS_PATH/sbin/radiusd -fx &
fi

