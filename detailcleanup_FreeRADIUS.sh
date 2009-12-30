#!/bin/sh
find /usr/local/var/log/radius/radacct/ -name 'detail-*' -mtime +15 -exec rm -f '{}' \;
