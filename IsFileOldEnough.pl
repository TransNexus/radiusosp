#!/usr/bin/perl
# IsFileOldEnough.pl
#
# This file is used by the delete_archived_radius_log_files.sh script to
# to determine if an archived log file is old enough to delete.


if( $#ARGV != 1)
{
  print "Usage: IsFileOldEnough MinAgeInDays FileName\n";
  exit -1;
}

#
# Assume that it is to early to delete the file
#
$exitStatus = 1;

#
# Extract input parameters
#
$minAgeInDays = $ARGV[0];
$fileName     = $ARGV[1];

#
# Get current time
#
$timeNow      = time;

#
# Get stats about the file
#
($dev,$ino,$mode,$nlink,$uid,
 $gid,$rdev,$size,$atime,
 $mtime,$ctime,$blksize,$blocks) = stat($fileName);

#
# Was stat successfull?
#
if( $ctime == NULL )
{
  print "Make sure that file: $fileName exists.\n";
  exit -1;
}

#
# Calculate time (in days) since last change to the file
#
$daysSinceLastUpdate = ($timeNow - $ctime) / (60 * 60 * 24);

#
# Compare actual age to the desired age
#
if($daysSinceLastUpdate > $minAgeInDays)
{
  $exitStatus = 0;
}

exit $exitStatus;

