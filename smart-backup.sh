#!/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
#
# This is a wrapper Bash script to combine the detect_inode_moves.py + Rsync
# when backupping some directory to the remote host via SSH
#
# The best results could be achieved if the Rsync binary (on the local and remote
# hosts) is patched to support --detect-renamed argument/functionality
#
# The script is desinged to be executed as root user
#
# Version: 1.0
# Copyright (C) 2021 Vat Vit
# License: GPLv2+
#

##################################################### SCRIPT BEGINS #####################################################

myself=`basename "$0"`
if [ "$1" == "" ]; then
    echo "Usage: $myself <path the the configuration file>"
    exit 1
fi
if ! grep -q "DETECT_INODE_MOVES_SCRIPT" "$1"; then
    echo "$1 file does not look a proper configuration file of smart-backup.sh script, aborting"
    exit 2
fi
source "$1"

if [ "$ONE_FILE_SYSTEM_ONLY" == "1" ]; then
    onefilesystemarg="--one-file-system"
else
    onefilesystemarg=""
fi
if [ "$RSYNC_DETECT_RENAMED_ENABLED" == "1" ]; then
    rsyncrenamepatchedargs="--detect-renamed"
else
    rsyncrenamepatchedargs=""
fi
mkdir -p $DETECT_INODE_DUMP_FILE_DIR
inodedumpfile="$DETECT_INODE_DUMP_FILE_DIR/inode-dump$(echo "$ROOT_DIR"|sed 's/\//_/g;s/[^[:print:]]//').txt"
if [ ! -f "$inodedumpfile" ]; then
    echo "Inode dump file ($inodedumpfile) does not exist, creating it for the first time..."
    inodedumpcmd="$DETECT_INODE_MOVES_SCRIPT -a dump -d "$ROOT_DIR" -o "$inodedumpfile" $onefilesystemarg"
    for i in "${EXCLUDED_DIRS[@]}"; do
        inodedumpcmd="$inodedumpcmd -e \"$i\""
    done
    eval nice -n 20 ionice -c 3 $inodedumpcmd
fi
if [ "$REMOTE_HOST_ROOT_DIR" != "" ]; then
    inodedetectchangerootdirarg="-r $REMOTE_HOST_ROOT_DIR"
else
    inodedetectchangerootdirarg=""
fi
if [ "$EXCLUDED_DIRS" == "" ]; then
    inodedetectrsyncfilearg=""
    inodedetectrsyncfile=""
    rsyncexlcudeddirfilearg=""
else
    inodedetectrsyncfile="${DETECT_INODE_DUMP_FILE_DIR}/rsync-excluded-dirs_$(echo "$ROOT_DIR"|sed 's/\//_/g;s/[^[:print:]]//').txt"
    inodedetectrsyncfilearg="-f $inodedetectrsyncfile"
    rsyncexlcudeddirfilearg="--exclude-from $inodedetectrsyncfile"
fi
inodedetectoutputscript="${DETECT_INODE_DUMP_FILE_DIR}/inode-move-script_$(echo "$ROOT_DIR"|sed 's/\//_/g;s/[^[:print:]]//').py"
inodedetectcmd="$DETECT_INODE_MOVES_SCRIPT -a detect -i "$inodedumpfile" $inodedetectchangerootdirarg -o "$inodedetectoutputscript" $inodedetectrsyncfilearg"
eval nice -n 20 ionice -c 3 $inodedetectcmd
if [ ! -f "$inodedetectoutputscript" ]; then
    echo "Could not find the output script generated by detect_inode_moves.py, this most probably means that there was error(s), check the output for them, aborting."
    rm -f "$inodedetectoutputscript"
    exit 3
fi
echo "Starting to generate the new inode dump file on the background already..."
inodedumpfiletmp="$DETECT_INODE_DUMP_FILE_DIR/inode-dump$(echo "$ROOT_DIR"|sed 's/\//_/g;s/[^[:print:]]//').txt.tmp"
inodedumpcmd="$DETECT_INODE_MOVES_SCRIPT -a dump -d "$ROOT_DIR" -o "$inodedumpfiletmp" $onefilesystemarg"
for i in "${EXCLUDED_DIRS[@]}"; do
    inodedumpcmd="$inodedumpcmd -e \"$i\""
done
eval nice -n 20 ionice -c 3 $inodedumpcmd > /dev/null &
inodedumppid=$!
inodedetectoutputscriptbn=$(basename "$inodedetectoutputscript")
echo "Copying the output script generated by detect_inode_moves.py ($inodedetectoutputscript) to the remote host, under ${REMOTE_HOST_TMP_DIR} directory"
$RSYNC_BINARY -a --verbose --rsync-path="$REMOTE_RSYNC_BINARY" "$inodedetectoutputscript" ${REMOTE_USERNAME}@${REMOTE_HOST}:"${REMOTE_HOST_TMP_DIR}/"
rt=$?
if [ $rt -ne 0 ]; then
    echo "There was error while copying the output script generated by detect_inode_moves.py to the remote host by using Rsync, check the output for error(s), aborting."
    rm -f "$inodedumpfiletmp" "$inodedetectoutputscript" "$inodedetectrsyncfile"
    exit 4
fi
echo "Executing the output script generated by detect_inode_moves.py remotely on the remote host by using SSH"
ssh ${REMOTE_USERNAME}@${REMOTE_HOST} "${REMOTE_HOST_TMP_DIR}/${inodedetectoutputscriptbn}"
echo "Running the actual Rsync now..."
if [ "$REMOTE_HOST_ROOT_DIR" == "" ]; then
    REMOTE_HOST_ROOT_DIR="$ROOT_DIR"
fi
rsyncmd="$RSYNC_BINARY $onefilesystemarg $rsyncrenamepatchedargs --rsync-path="$REMOTE_RSYNC_BINARY"  $rsyncexlcudeddirfilearg  --fuzzy -HAav --delay-updates --delete-delay --numeric-ids "${ROOT_DIR}/" ${REMOTE_USERNAME}@${REMOTE_HOST}:"${REMOTE_HOST_ROOT_DIR}""
eval nice -n 20 ionice -c 3 $rsyncmd
rt=$?
echo "Removing the output script generated by detect_inode_moves.py from the remote host"
ssh ${REMOTE_USERNAME}@${REMOTE_HOST} rm -f "${REMOTE_HOST_TMP_DIR}/${inodedetectoutputscriptbn}"
if [ $rt -eq 0 ] || [ $rt -eq 23 ] || [ $rt -eq 24 ]; then
    echo "Rsync completed successfully"
else
    echo "Rsync exit code was $rt which means most probably error(s), check the output for errors, aborting."
    rm -f "$inodedumpfiletmp" "$inodedetectoutputscript" "$inodedetectrsyncfile"
    exit 5
fi
echo -n "Waiting for the new inode dump to be finished... "
wait $inodedumppid
echo "Done"
rm -f "$inodedumpfile"
echo "Moving the updated inode dump file to $inodedumpfile"
mv "$inodedumpfiletmp" "$inodedumpfile"
echo "Cleaning up the temporary files"
rm -f "$inodedumpfiletmp" "$inodedetectoutputscript" "$inodedetectrsyncfile"
echo "Script finished"
