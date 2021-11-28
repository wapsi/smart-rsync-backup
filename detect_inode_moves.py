#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__    = 'Miikka Veijonen, Pavel Kr'
__version__   = '2.0'
__copyright__ = 'Copyright: (C) 2021 Miikka Veijonen, Pavel Krc'
__license__   = 'GPLv2+'

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import hashlib
import re
import sys
import signal
import threading
import time
import datetime
import shutil
import random
import string
import argparse

inode_move_script_begin = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import shutil
import random
import string
import re
import sys

fmoves = {}
finalfmoves = {}
finalfmovesrev = {}
failedmoves = {}

def id_generator(size=8, chars=string.ascii_letters + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))
    
def prepare_move(a, b):
    global fmoves
    global finalfmoves
    global finalfmovesrev
    global failedmoves
    srcdir = os.path.dirname(a)
    dstdir = os.path.dirname(b)
    dsttmpdir = dstdir
    fname = os.path.basename(a)
    while True:
        if dsttmpdir == '/':
            break
        if re.match('^' + dsttmpdir + '/', srcdir + '/'):
            break
        dsttmpdir = os.path.dirname(dsttmpdir)
    while True:
        ftmp = dsttmpdir + '/.' + fname + '_' + id_generator()
        if not os.path.isdir(ftmp) and not os.path.isfile(ftmp) and not os.path.islink(ftmp):
            break
    print('Temporarily moving file: ' + a + ' => ' + ftmp)
    try:
        os.rename(a, ftmp)
    except:
        print('Could not move temporarily file: ' + a + ' => ' + ftmp)
        failedmoves[a] = b
    else:
        finalfmoves[a] = ftmp
        finalfmovesrev[ftmp] = a
        fmoves[a] = b
        
def finish_moves():
    global fmoves
    global finalfmoves
    global finalfmovesrev
    global failedmoves
    for f in finalfmoves:
        skipthis = False
        for ff in failedmoves:
            if re.match('^' + ff, fmoves[f]):
                print('Previously failed (and reverted) file move (' + ff + ') is part of this file\\'s final move destination: ' + finalfmoves[f] + ' => ' + fmoves[f] + ', skipping this one (and reverting the temp move: ' + finalfmoves[f] + ' => ' + f +')')
                try:
                    os.rename(finalfmoves[f], f)
                except:
                    print('Could not revert the temp move: ' + finalfmoves[f] + ' => ' + f)
                skipthis = True
                break
        if skipthis:
            continue
            
        if os.path.isdir(fmoves[f]):
            try:
                shutil.rmtree(fmoves[f])
            except Exception as e:
                print('Could not remove destination before the final file move, the file move will fail: ' + finalfmoves[f] + ' => ' + fmoves[f])
        fdestdir = os.path.dirname(fmoves[f])
        if not os.path.isdir(fdestdir):
            try:
                print('Creating directory (recursively): ' + fdestdir)
                os.makedirs(fdestdir)
            except:
                print('Could not create the destination directory (' + fdestdir + '), the file move will fail')
        try:
            print('Moving temporarily moved file to its final location: ' + finalfmoves[f] + ' => ' + fmoves[f])
            os.rename(finalfmoves[f], fmoves[f])
        except:
            print('Could not perform final move (reverting the temp move): ' + finalfmoves[f] + ' => ' + f)
            try:
                os.rename(finalfmoves[f], f)
            except:
                print('Could not revert the temp move: ' + finalfmoves[f] + ' => ' + f)
            else:
                failedmoves[f] = finalfmovesrev[finalfmoves[f]]

'''

def find_mount_point(path):
    path = os.path.abspath(path)
    orig_dev = os.stat(path).st_dev

    while path != '/':
        dir = os.path.dirname(path)
        if os.stat(dir).st_dev != orig_dev:
            # we crossed the device border
            break
        path = dir
    return path

def find_files_with_exceptions(rootdir, d, edirsenabled, cexcludeddirsregex, rsyncefile, rsyncefilehandle):
    global filecount
    global dircount
    global lutime

    dmountpoint = find_mount_point(d)
    dmountpointhash = hashlib.sha256(dmountpoint.encode('utf-8')).hexdigest()

    stlog('VERBOSE', 'Scanning directory: ' + d)
    filehashes = {}
    try:
        fds = os.scandir(d)
    except Exception as e:
        stlog('WARNING', 'Could not go in to directory: ' + d + ' (' + str(e) + ')')
        return False
    for f in fds:
        try:
            ttt = f.path.encode('UTF-8').decode('UTF-8')
        except Exception as e:
            stlog('WARNING', 'Could not read filename/path properly (most probably some charset issue): ' + f.path.encode('UTF-8','ignore').decode('UTF-8') + ' (' + str(e).encode('UTF-8','ignore').decode('UTF-8') + ')')
            continue
        if (lutime + 10) < int(time.time()):
            stlog('INFO', 'Scanning... (scanned: ' + str(dircount) + ' directories and ' + str(filecount) + ' files, currently scanning directory: ' + d + ')')
            lutime = int(time.time())
        if f.is_file() and not f.is_symlink():
            filecount +=1
            finode = os.lstat(f.path).st_ino
            filehashes[f.path] = [ dmountpointhash, finode ]
        elif f.is_dir():
            if f.is_symlink():
                stlog('VERBOSE', 'Directory is a symlink, not following: ' + f.path)
                continue
            if edirsenabled and re.match(cexcludeddirsregex, f.path):
                stlog('INFO', 'Directory excluded, not scanning: ' + f.path)
                if rsyncefile:
                    rsyncline = re.sub("^" + rootdir , '', f.path.encode('UTF-8','ignore').decode('UTF-8'))
                    rsyncefilehandle.write(rsyncline + "/\n")
                continue
            dircount +=1
            try:
                fsubdirhashes = find_files_with_exceptions(rootdir, f.path, edirsenabled, cexcludeddirsregex, rsyncefile, rsyncefilehandle)
            except:
                continue
            if type(filehashes) is dict:
                filehashes.update(fsubdirhashes)
        else:
            continue
    return filehashes

def id_generator(size=8, chars=string.ascii_letters + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

def find_for_moved_files(origfilehashes, filehashes, rootdirold, rootdirnew):
    global verbose_mode
    global lutime
    
    filestobemoved = {}
    movedfdc = 0
    mtc = len(origfilehashes)
    for of in list(origfilehashes):
        movedfdc +=1
        if (lutime + 10) < int(time.time()):
            stlog('INFO', 'Detecting moved files... (scanned: ' + str(movedfdc) + '/' + str(mtc) + ' files)')
            lutime = int(time.time())
        ffound=False
        ofnpath = re.sub('^' + rootdirnew + '/', rootdirold + '/', of)
        if not of in origfilehashes:
            # Already removed file/key
            continue
        if os.path.isfile(ofnpath) and not os.path.islink(ofnpath):
            try: 
                filehashes[ofnpath][0]
            except:
                pass
            else:
                if origfilehashes[of][0] == filehashes[ofnpath][0] and origfilehashes[of][1] == filehashes[ofnpath][1]:
                    # Found an existing file which is still in the same location as well
                    origfilehashes.pop(of)
                    filehashes.pop(ofnpath)
                    continue
        for f in list(filehashes):
            if not f in filehashes:
                break
            if origfilehashes[of][0] == filehashes[f][0] and origfilehashes[of][1] == filehashes[f][1]:
                oldfilewithorigrootdir = re.sub('^' + rootdirold + '/', rootdirnew + '/', of)
                newfilewithorigrootdir = re.sub('^' + rootdirold + '/', rootdirnew + '/', f)
                stlog('VERBOSE', 'Found moved file: ' + oldfilewithorigrootdir + ' => ' + newfilewithorigrootdir)
                filestobemoved[newfilewithorigrootdir] = oldfilewithorigrootdir
                origfilehashes.pop(of)
                #try:
                #    origfilehashes.pop(newfilewithorigrootdir)
                #except:
                #    pass
                filehashes.pop(f)
                ffound=True
                break
        if ffound == False:
            stlog('VERBOSE', 'File ' + of + ' has been removed')
    stlog('INFO', 'File move detection finished (scanned: ' + str(movedfdc) + '/' + str(mtc) + ' files)')
    return filestobemoved


def write_move_file(filestobemoved, outputsourcereffilehandle, rootdir):
    #print(filestobemoved)
    global lutime
    delaymovedfiles = {}
    tempmovedfiles = {}
    sortedfilestobemoved = sorted(filestobemoved, key=lambda x: (-x.count('/')))
    tam = len(filestobemoved)
                    
    outputsourcereffilehandle.write('%s\n' % inode_move_script_begin)
    
    cline = 'if not os.path.isdir(\'' + rootdir + '\'):\n    print(\'ERROR: Root directory ' + rootdir + ' is not a directory or it does not exist, aborting.\')\n    sys.exit(1)\n\n'
    outputsourcereffilehandle.write(cline)
    
    tpc = 0
    for f in sortedfilestobemoved:
        tpc +=1
        if (lutime + 10) < int(time.time()):
            stlog('INFO', 'Writing the output file... (written ' + str(tpc) + '/' + str(tam) + ' file moves already)')
            lutime = int(time.time())
        #renl = 'prepare_move(\'' + tempmovedfiles[delaymovedfiles[f]].encode('UTF-8','ignore').decode('UTF-8').replace("'", "\\'") + '\', \'' + f.encode('UTF-8','ignore').decode('UTF-8').replace("'", "\\'")  + '\')\n'
        renl = 'prepare_move(\'' + filestobemoved[f].encode('UTF-8','ignore').decode('UTF-8').replace("'", "\\'") + '\', \'' + f.encode('UTF-8','ignore').decode('UTF-8').replace("'", "\\'")  + '\')\n'
        outputsourcereffilehandle.write(renl)
    outputsourcereffilehandle.write('finish_moves()\n')
    
    stlog('INFO', 'Output file writing finished (wrote: ' + str(tpc) + '/' + str(tpc) + ' file moves)')

def main_thread(rootdir, edirsenabled, cexcludeddirsregex, inputsourcereffile, outputsourcereffile, rsyncefile):
    global verbose_mode
    global filecount
    global dircount
    global lutime

    filehashesnew = {}
    filecount = 0
    dircount = 0
    lutime = int(time.time())

    if outputsourcereffile != None and inputsourcereffile == None:
        if not os.path.isdir(rootdir):
            stlog('ERROR', 'Root directory does not exists: ' + rootdir)
            return False
        rsyncefilehandle=False
        stlog('INFO', 'Starting to scan the files from the root dir: ' + rootdir)
        # Reading the filepaths, inodes and mount hashes
        try:
            filehashesnew = find_files_with_exceptions(rootdir, rootdir, edirsenabled, cexcludeddirsregex, rsyncefile, rsyncefilehandle)
        except Exception as e:
            stlog('ERROR', 'Could not scan ' + rootdir + ' for directories and files (' + str(e) + ')')
            return False
        else:
            if filehashesnew == False:
                stlog('ERROR', 'Could not scan ' + rootdir + ' for directories and files')
                return False
            stlog('INFO', 'Root dir scan finished (scanned ' + str(dircount) + ' directories which contained in total ' + str(filecount) + ' files)')
        stlog('INFO', 'Writing the scan result to inode dump file: ' + outputsourcereffile)
        # Saving the data to the inode dump file
        try:
            filelistfile = open(outputsourcereffile, "w")
        except Exception as e:
            stlog('ERROR', 'Could not open output inode dump writing: ' + outputsourcereffile + ' (' + str(e) + ')')
            return False
        filelistfile.write(rootdir + '\n')
        if edirsenabled:
            filelistfile.write('%s\n' % cexcludeddirsregex)
        else:
            filelistfile.write('%s\n' % ['__NO-EXCLUDED-DIRS__'])
        for f in filehashesnew:
            try:
                fenc = f.encode('UTF-8').decode('UTF-8')
            except Exception as e:
                stlog('ERROR', 'Could not store filename/path properly (most probably some charset issue): ' + f.encode('UTF-8','ignore').decode('UTF-8') + ' (' + str(e) + ')')
                continue
            filelistfile.write(filehashesnew[f][0] + ' ' + str(filehashesnew[f][1]) + ' ' + f + '\n')
        filelistfile.close()
        return
    
    elif inputsourcereffile != None and outputsourcereffile != None:
        # Reading the old filepath, inode and mount hash information from the inode dump file
        filehashesold = {}
        rsyncefilehandle=False
        if rsyncefile:
            stlog('INFO', 'Writing the Rsync dir exclusion file to: ' + rsyncefile)
            try:
                rsyncefilehandle = open(rsyncefile, "w")
            except Exception as e:
                stlog('ERROR', 'Could not open Rsync dir exclusion file for the writing: ' + rsyncefile + ' (' + str(e) + ')')
                return False
        stlog('INFO', 'Reading the inode dump file: ' + inputsourcereffile)
        try:
            f = open(inputsourcereffile, "r")
        except Exception as e:
            stlog('ERROR', 'Could not open inode dump file for the reading: ' + inputsourcereffile + ' (' + str(e) + ')')
            return False       
        fr = 0
        for l in f:
            if fr == 0:
                rootdirold = l.rstrip('\n')
                fr = 1
                continue
            elif fr == 1:
                cexcludeddirsregex = l.rstrip('\n')
                if (cexcludeddirsregex == '[\'__NO-EXCLUDED-DIRS__\']'):
                    edirsenabled=False
                else:
                    edirsenabled=True
                fr = -1
                continue
            la = l.split(' ', 2)
            filehashesold[la[2].rstrip('\n')] = [ la[0], int(la[1]) ]
        f.close()
        if not rootdir:
            rootdir = rootdirold
        stlog('INFO', 'Starting to re-scan the files from the original root directory: ' + rootdirold)
        # Reading the current filepaths, inodes and mount hashes
        try:
            filehashesnew = find_files_with_exceptions(rootdirold, rootdirold, edirsenabled, cexcludeddirsregex, rsyncefile, rsyncefilehandle)
        except Exception as e:
            stlog('ERROR', 'File scan failed (' + str(e) + ')')
            return False
        else:
            if filehashesnew == False:
                stlog('ERROR', 'Could not scan ' + rootdirold + ' for directories and files')
                return False
            stlog('INFO', 'Originial root directory scan finished (scanned ' + str(dircount) + ' directories which contained in total ' + str(filecount) + ' files)')
        
        try:
            outputsourcereffilehandle = open(outputsourcereffile, "w")
        except Exception as e:
            stlog('ERROR', 'Could not open output rename script for writing: ' + outputsourcereffile + ' (' + str(e) + ')')
            return False

        stlog('INFO', 'Detecting the moved files and preparing the moves if found...')
        filestobemoved = {}
        filestobemoved = find_for_moved_files(filehashesold, filehashesnew, rootdirold, rootdir)
        if len(filestobemoved) > 0:
            stlog('INFO', 'Writing the file moving script...')
            write_move_file(filestobemoved, outputsourcereffilehandle, rootdir)
        else:
            stlog('INFO', 'No moved files found, nothing to do')
            
        outputsourcereffilehandle.close()

    return

def quit_func(signum, frame):
    stlog('WARNING', 'Script interruped, aborting.\n')
    sys.exit(0)
    
def stlog(level, msg):
    global verbose_mode
    global begin_time
    if level == 'VERBOSE':
        if verbose_mode:
            print(str(datetime.datetime.now() - begin_time) + ' ' + level + ': ' + msg, end="\n", flush=True)
    else:
        print(str(datetime.datetime.now() - begin_time) + ' ' + level + ': ' + msg, end="\n", flush=True)

verbose_mode = False
begin_time = datetime.datetime.now()

def main():
    global verbose_mode
    global  __version__
    global __copyright__
    global __license__
    # Parsing arguments
    my_parser = argparse.ArgumentParser()
    my_parser = argparse.ArgumentParser(description='File move(s) detection and execution script (designed to be executed before the actual Rsync is executed), Version: ' + __version__ + ', ' + __copyright__ + ', License: '+ __license__)
    my_parser.add_argument('-d', '--root-dir', action='store', type=str, help='Specify the root dir (when reading existing inode dump file, this can be set to the target system\'s root dir so the correct rootdir will be set to the output rename script file).')
    my_parser.add_argument('-e','--excluded-dirs',action='append',type=str, help='Set the directories that should be excluded from the source directory scan, in regular expression (regexp) format (example: -e ".*/\.btrfs$" -e "^/home/user/tmp$"). NOTE: can be set multiple times for multiple exclusions if needed and this setting has effect only when "--source-dir" is used. NOTE2: the exclusions are saved to the "output source dir reference file" if it is used.')
    my_parser.add_argument('-o', '--output-file', action='store', type=str, required=True, help='Set the output inode dump file location, or if used with -i / --input-file argument, this will define the output rename script file\'s location')
    my_parser.add_argument('-i', '--input-file', action='store', type=str, help='Set the input inode dump file location. This is used in combination with -o / --output-file argument.')
    my_parser.add_argument('-r', '--dir-exclusion-file-for-rsync', action='store', type=str, required=False, help='Set the output file for excluded dir list file for Rsync. NOTE: This should be used only during file move detection phase (=both -i / --input-file and -o / --output-file arguments are set) and when -e / --excluded-dirs argument(s) are used.')
    my_parser.add_argument('--verbose', action='store_true', required=False, help='Run the script in verbose mode')
    args = my_parser.parse_args()
    
    rootdir = args.root_dir
    outputsourcereffile = args.output_file
    inputsourcereffile = args.input_file
    
    # Checking arguments and required / prohibited combinations
    if args.dir_exclusion_file_for_rsync:
        rsyncefile=args.dir_exclusion_file_for_rsync
    else:
        rsyncefile=False
    
    if inputsourcereffile == None and rsyncefile != False:
        print('-r / --dir-exclusion-file-for-rsync can be used only during inode dump')
        quit(1)
    
    elif inputsourcereffile == None and rootdir == None:
        print('-d / --root-dir must be set for inode dump (no -i / --input-file is set)')
        quit(1)

    if rootdir != None:
        rootdir = rootdir.rstrip('/')
    else:
        rootdir = False
        
    if args.verbose:
        verbose_mode = True
    else:
        verbose_mode = False
        
    if args.excluded_dirs:
        edirsenabled=True
        excluded_dirs_regex = args.excluded_dirs
        cexcludeddirsregex = "(" + ")|(".join(excluded_dirs_regex) + ")"
    else:
        cexcludeddirsregex = ""
        edirsenabled=False
    
    stlog('INFO', 'Script execution started')
        
    # Performing the scanning, hashing, move detection and file renaming in a separate thread
    # because it's very I/O instensive operation and the interruption of the script by using CTRL+C
    # is not working very well.
    work_thread = threading.Thread(target=main_thread, args=(rootdir, edirsenabled, cexcludeddirsregex, inputsourcereffile, outputsourcereffile, rsyncefile))
    work_thread.daemon = True
    work_thread.start()
    signal.signal(signal.SIGINT, quit_func)
    while True:
        time.sleep(1)
        if not work_thread.is_alive():
            stlog('INFO', 'Script exectuion finished')
            sys.exit(0)

if __name__ == "__main__":
    main()
