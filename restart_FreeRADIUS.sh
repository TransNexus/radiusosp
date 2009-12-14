#!/bin/bash
# restart_FreeRADIUS.sh
#
# This script checks if FreeRADIUS is running.
# If the application is not running, it restarts it.
#
# This script must be run by a user root


#
if pgrep radiusd >/dev/null 2>&1
        then
                # Do nothing, the radius server is running
        exit 1
fi
        echo "!!!FreeRADIUS is not running!!!"
        echo "The application will be restarted"

/usr/local/sbin/radiusd -fx &

