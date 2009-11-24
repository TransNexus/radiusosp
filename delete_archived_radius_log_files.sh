#!/bin/sh
# delete_archived_radius_log_files.sh
#
# This script automates the process of deleting archived files from the
# $RADIUS_HOME/var/log/radius directory that have a .gz extension and have been 
# unchanged for more days than the number of days defined by the 
# DELETE_FILES_OLDER_THAN_DAYS variable.  The default value for 
# this variable is 45 days.
#
# For example, if this script is run with DELETE_FILES_OLDER_THAN_DAYS=45
# all .gz files that have not been changed, compressed, renamed, etc. for
# more than 45 days will be deleted.
#
# This script can be run by user ossadmin.  This script uses the 
# IsFileOldEnough.pl script which must also be located in the 
# $RADIUS_HOME/utils directory.
 
DELETE_FILES_OLDER_THAN_DAYS=7
FILE_MASK=../var/log/radius/*.gz*

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
 
for file in $FILE_MASK
do 
  if ./IsFileOldEnough.pl $DELETE_FILES_OLDER_THAN_DAYS $file
  then rm ./$file
  fi
done


