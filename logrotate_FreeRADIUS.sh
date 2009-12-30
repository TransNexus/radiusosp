#!/bin/sh
# logrotate_FreeRADIUS.sh
#
#
# This logrotate script is used to rotate FreeRADIUS radius.log file.
# It should be triggered by cron of ossadmin daily when installed in SINGLE_PACKAGE mode.
# It should be triggered by cron of root daily if installed in FreeRADIUS only mode.
#
# The Radius log file, radius.log, grows continuously and can become
# too large to view after several months of normal operation.  This
# script, when run periodically, solves this operational problem by 
# renaming and saving the current log file and allowing Radius
# server to start a new radius.log file.
#
# When this file is run, the current radius.log file is renamed and then
# gzipped.  The file name for the backup is radius.log-YYYYMMDD-HH:MM.gz.
# Where YYYYMMDD-HH:MM stands for the year, month, day, hour and minute 
# when the log file was backed up.  When the radius.log file is renamed 
# and backed up, a new radius.log file is automatically written in the 
# $RADIUS_HOME/freeradius/var/log/radius directory if in SINGLE_PACKAGE mode,
# or in /usr/local/var/log/radius directory if in FreeRADIUS only mode.
#
# This script must be run by user ossadmin.

BACKUP_LOG_FILE_NAME=radius.log-`date '+%Y%m%d-%H:%M'`

if [ ! "$RADIUS_HOME" ]
then
        echo "The RADIUS_HOME variable is not set."
        exit 1
fi

if [ ! -d $RADIUS_HOME/utils ]
then
        echo "Directory $RADIUS_HOME/utils does not exist"
        echo "Make sure that RADIUS_HOME variable is correctly set."
        exit 1
fi
 
cd $RADIUS_HOME/utils

## Uncomment the next line if using the SINGLE_PACKAGE 
#cd ../var/log/radius

## Uncomment the next line if using the SINGLE_PACKAGE 
#mv ../var/log/radius/radius.log $BACKUP_LOG_FILE_NAME

## Uncomment the next line if using stand alone Radius
mv /usr/local/var/log/radius/radius.log $BACKUP_LOG_FILE_NAME
 
gzip $BACKUP_LOG_FILE_NAME
