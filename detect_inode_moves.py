#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''Detects renamed and/or moved files by tracking inodes. This information
can be then used to make smarter Rsync backups for example (so the moved
or renamed files or directories won't be transferred again over the network
by Rsync).

Creates a python script to replay similar changes. Make sure to use relative
paths if you want to replay changes in a different absolute location or use
--rename-script-rootdir to set the different destination path used
in the final script. Does not follow symbolic links and skips files which has
hard links (Rsync will handle them better).

Set --one-file-system if you want to dump files from the cross/sub
mounts within the root directory (the script will use sha256 checksum of the
mount to avoid inode collosions).

Set directories you want to exclude from the dump/detection by using
--excluded-dirs argument.

This script has been tested only on GNU/Linux and won't work properly on
Windows (because of reading the mount points from the virtual file:
/proc/mounts which does not exist in Windows!)
'''
__author__    = 'Pavel Krc'
__email__     = 'src@pkrc.net'
__version__   = '1.2-wapsi-edition'
__copyright__ = 'Copyright (C) 2021 Pavel Krc'
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

import sys
import os
import re
import hashlib
import argparse

# Getting mount points from /proc/mounts because os.path.ismount
# is not working properly with bind mounts on Linux
with open('/proc/mounts','r') as f:
    mntpoints = [line.split()[1] for line in f.readlines()]

hardlinkrefc=-1

script_header = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
def ren(a, b):
    print(\'Move: \' + a + \' => \' + b)
    assert(not os.path.exists(b))
    os.rename(a, b)
def mkd(d):
    print(\'Create dir: \' + d)
    os.mkdir(d)

'''
mv_cmd = 'try:\n    ren("{0}", "{1}")\nexcept:\n    print(\'WARNING: Could not move file {0} to {1}\')\n'
mkdir_cmd = 'try:\n    mkd("{0}")\nexcept:\n    print(\'WARNING: Could not create directory {0}\')\n'
escaped_chars = re.compile(r'(["\\])')
esc = lambda s: escaped_chars.sub(r'\\\1', s)

def walk_dirs(dirtoscan, logfilehandle):
    global hardlinkrefc
    global edirsenabled
    global excluded_dirs_regex
    global cexcludeddirsregex
    global one_file_system_only

    currentmnt = find_mount_point(dirtoscan)
    currentmnthash = hashlib.sha256(currentmnt.encode('utf-8')).hexdigest()

    for f in os.scandir(dirtoscan):
        if f.is_symlink():
            continue
        elif f.is_file():
            if has_file_hardlinks(f.path):
                inot = hardlinkrefc
                hardlinkrefc -= 1
            else:
                inot = os.lstat(f.path).st_ino
            logfilehandle.write('F {0} {1:d} {2}\n'.format(currentmnthash, inot, f.path.encode('UTF-8','ignore').decode('UTF-8')))
        elif f.is_dir(follow_symlinks=False):
            if edirsenabled and re.match(cexcludeddirsregex, f.path):
                print('Directory excluded, not scanning: ' + f.path)
                continue
            if f.path[0] != '/':
                pathabs=os.getcwd() + '/' + f.path
            else:
                pathabs=f.path
            if pathabs in mntpoints:
                if one_file_system_only:
                    print('The following directory contains a separate mount and --one-file-system is set, so skipping it: ' + f.path)
                    logfilehandle.write('D {0} {1:d} {2}\n'.format(currentmnthash, os.lstat(f.path).st_ino, f.path.encode('UTF-8','ignore').decode('UTF-8')))
                    continue
                else:
                    print('The following directory contains a separate mount and --one-file-system is not set, so scanning it as well: ' + f.path)

            dcurrentmnt = find_mount_point(f.path)
            dcurrentmnthash = hashlib.sha256(dcurrentmnt.encode('utf-8')).hexdigest()
            logfilehandle.write('D {0} {1:d} {2}\n'.format(dcurrentmnthash, os.lstat(f.path).st_ino, f.path.encode('UTF-8','ignore').decode('UTF-8')))
            walk_dirs(f.path, logfilehandle)

def dump_inodes(root, log_path):
    global edirsenabled
    global cexcludeddirsregex
    global excluded_dirs_regex
    global one_file_system_only
    # must be top-down for reconstruction
    with open(log_path, 'w') as o:
        currentmnt = find_mount_point(root)
        currentmnthash = hashlib.sha256(currentmnt.encode('utf-8')).hexdigest()
        o.write('%s\n' % one_file_system_only)
        if edirsenabled:
            o.write('%s\n' % cexcludeddirsregex)
        else:
            o.write('%s\n' % ['__NO-EXCLUDED-DIRS__'])
        o.write('D {0} {1:d} {2}\n'.format(currentmnthash, os.lstat(root).st_ino, root))
        walk_dirs(root, o)

def has_file_hardlinks(filename):
    if os.stat(filename).st_nlink > 1:
        return True
    else:
        return False

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

class DirEntry(object):
    __slots__ = ['path', 'parent', 'dirs', 'files']
    def __init__(self, path, parent):
        self.path = path
        self.parent = parent
        self.dirs = set()
        self.files = set()

class FileEntry(object):
    __slots__ = ['path', 'parent']
    def __init__(self, path, parent):
        self.path = path
        self.parent = parent

class MovingTree(object):
    def __init__(self, log_path):
        global one_file_system_only
        global cexcludeddirsregex
        global edirsenabled

        self.newfiles = []
        self.ok_dirs = self.ok_files = 0

        self.dirs = {}
        self.files = {}
        revdirs = {}

        with open(log_path, 'r') as i:
            # one-file-system
            oft = next(i).rstrip('\n')
            if oft == 'True':
                one_file_system_only=True
            else:
                one_file_system_only=False
            # excluded dirs
            cexcludeddirsregex = next(i).rstrip('\n')
            if (cexcludeddirsregex == '[\'__NO-EXCLUDED-DIRS__\']'):
                edirsenabled=False
            else:
                edirsenabled=True
            # root entry
            df, mnthash, ino, path = next(i).rstrip('\n').split(' ', 3)
            akey = mnthash + '_' + ino
            ino = int(ino)
            assert df == 'D'
            self.root = path
            self.dirs[akey] = DirEntry(path, None)
            revdirs[path] = akey
            for ln in i:
                df, mnthash, ino, path = ln.rstrip('\n').split(' ', 3)
                akey = mnthash + '_' + ino
                ino = int(ino)
                parent_akey = revdirs[path.rsplit('/', 1)[0]]
                if df == 'D':
                    self.dirs[akey] = DirEntry(path, parent_akey)
                    revdirs[path] = akey
                    self.dirs[parent_akey].dirs.add(akey)
                elif df == 'F':
                    self.files[akey] = FileEntry(path, parent_akey)
                    self.dirs[parent_akey].files.add(akey)
                else:
                    raise RuntimeError()

    def create_script(self, script_path):
        # uses os.open to create executable script - still, read it first!
        cls = lambda: None
        try:
            fd = os.open(script_path, os.O_CREAT|os.O_WRONLY|os.O_TRUNC, 0o755)
            cls = lambda: os.close(fd)
            o = os.fdopen(fd, 'w')
            cls = o.close
            o.write(script_header)
            self.detect_changes(o)
        finally:
            cls()

    def update_children(self, entry, orig_p, new_p):
        l = len(orig_p)
        for i in entry.dirs:
            centry = self.dirs[i]
            assert centry.path[:l] == orig_p
            centry.path = new_p + centry.path[l:]
            self.update_children(centry, orig_p, new_p)
        for i in entry.files:
            centry = self.files[i]
            assert centry.path[:l] == orig_p
            centry.path = new_p + centry.path[l:]

    def check_dirs(self, dirtoscan, script, rsyncefilehandle=False):
        global edirsenabled
        global cexcludeddirsregex
        global replace_root_dir_of_final_script
        global rsyncefile

        currentmnt = find_mount_point(dirtoscan)
        currentmnthash = hashlib.sha256(currentmnt.encode('utf-8')).hexdigest()

        for f in os.scandir(dirtoscan):
            if f.is_symlink():
                continue

            elif f.is_file():
                ino = os.lstat(f.path).st_ino
                p = f.path.encode('UTF-8','ignore').decode('UTF-8')
                akey = currentmnthash + '_' + str(ino)
                try:
                    orig_entry = self.files.pop(akey)
                except KeyError:
                    # new file - just log
                    self.newfiles.append(p)
                else:
                    # existing file
                    if orig_entry.path == p:
                        self.ok_files += 1
                    else:
                        # moved
                        if replace_root_dir_of_final_script:
                            replace_root_dir_of_final_script
                            rorigpath = re.sub("^" + self.root , replace_root_dir_of_final_script, orig_entry.path)
                            rnewpath = re.sub("^" + self.root , replace_root_dir_of_final_script, p)
                            script.write(mv_cmd.format(esc(rorigpath), esc(rnewpath)))
                        else:
                            script.write(mv_cmd.format(esc(orig_entry.path), esc(p)))
                        # disparent self
                        try:
                            parent_entry = self.dirs[orig_entry.parent]
                        except KeyError:
                            pass #parent already processed
                        else:
                            parent_entry.files.remove(akey)

            elif f.is_dir(follow_symlinks=False):
                if edirsenabled and re.match(cexcludeddirsregex, f.path):
                    if rsyncefile:
                        rsyncline = re.sub("^" + self.root , '', f.path.encode('UTF-8','ignore').decode('UTF-8'))
                        rsyncefilehandle.write(rsyncline + "/\n")
                        print('Directory excluded, not scanning: ' + f.path.encode('UTF-8','ignore').decode('UTF-8') + ' (added it into Rsync excluded dir files too, because --dir-exclusion-file-for-rsync argument was set)')
                    else:
                        print('Directory excluded, not scanning: ' + f.path.encode('UTF-8','ignore').decode('UTF-8'))
                    continue
                if f.path[0] != '/':
                    pathabs=os.getcwd() + '/' + f.path
                else:
                    pathabs=f.path
                if pathabs in mntpoints:
                    if one_file_system_only:
                        print('The following directory contains a separate mount and --one-file-system was set on the dump phase, so skipping it: ' + f.path)
                        continue
                    else:
                        print('The following directory contains a separate mount and --one-file-system was not set on the dump phase, so scanning it as well: ' + f.path)
                dcurrentmnt = find_mount_point(f.path)
                dcurrentmnthash = hashlib.sha256(dcurrentmnt.encode('utf-8')).hexdigest()
                ino = os.lstat(f.path).st_ino
                akey = dcurrentmnthash + '_' + str(ino)
                p = f.path.encode('UTF-8','ignore').decode('UTF-8')
                try:
                    orig_entry = self.dirs.pop(akey)
                except KeyError:
                    # new directory
                    if replace_root_dir_of_final_script:
                        replace_root_dir_of_final_script
                        rnewpath = re.sub("^" + self.root , replace_root_dir_of_final_script, p)
                        script.write(mkdir_cmd.format(esc(rnewpath)))
                    else:
                        script.write(mkdir_cmd.format(esc(p)))
                else:
                    # existing directory
                    if orig_entry.path == p:
                        self.ok_dirs += 1
                    else:
                        # moved
                        if replace_root_dir_of_final_script:
                            replace_root_dir_of_final_script
                            rorigpath = re.sub("^" + self.root , replace_root_dir_of_final_script, orig_entry.path)
                            rnewpath = re.sub("^" + self.root , replace_root_dir_of_final_script, p)
                            script.write(mv_cmd.format(esc(rorigpath), esc(rnewpath)))
                        else:
                            script.write(mv_cmd.format(esc(orig_entry.path), esc(p)))
                        # disparent self
                        try:
                            parent_entry = self.dirs[orig_entry.parent]
                        except KeyError:
                            pass #parent already processed
                        else:
                            parent_entry.dirs.remove(akey)
                        # moving under either freshly created or already
                        # processed dir, so no need to register under new
                        # parent.
                        # update all children in the source tree
                        self.update_children(orig_entry, orig_entry.path+'/', p+'/')

                self.check_dirs(f.path, script, rsyncefilehandle)

    def detect_changes(self, script):
        # The order of detecting changes is important. The safest order I could
        # think of was to start top-bottom according to destination (i.e.
        # safely constructing new state with guaranteed existing parents),
        # updating source data structures where necessary.
        print('Detecting file/dir moves/renames from root directory: ' + self.root)
        if rsyncefile:
            rsyncefilehandle = open(rsyncefile, "w")
        else:
            rsyncefilehandle = False
        self.check_dirs(self.root, script, rsyncefilehandle)
        if rsyncefile:
            rsyncefilehandle.close()

        # list remaining unprocessed
        script.write('\n### Deleted (or excluded) directories ###\n')
        for p in sorted(e.path for e in self.dirs.values()
                if e.path != self.root):
            script.write('#{0}\n'.format(p))
        script.write('\n### Deleted files (or existing hard links) ###\n')
        for p in sorted(e.path for e in self.files.values()):
            script.write('#{0}\n'.format(p))
        script.write('\n### Newly created files (or hard links to existing files) ###\n')
        for p in self.newfiles:
            script.write('#{0}\n'.format(p))
        script.write('\n### {0:d} dirs and {1:d} files have remained in place. ###\n'
                .format(self.ok_dirs, self.ok_files))

if __name__ == '__main__':
    my_parser = argparse.ArgumentParser(description='Inode move detection script for smarter Rsync/backups')
    my_parser = argparse.ArgumentParser()
    my_parser.add_argument('-a', '--action', action='store', choices=['dump', 'detect'], type=str, required=True, help='Specify the action to be performed: dump or detect (this argument is always required)')
    my_parser.add_argument('-o', '--output', action='store', type=str, required=True, help='Specify the output file for inode dump file or the detection output script (this argument is always required)')
    my_parser.add_argument('-d', '--root-dir', action='store', type=str, help='Set the root directory for the inode dump (required when the action is "dump" and has no effect when the acton is "detect")')
    my_parser.add_argument('-e','--excluded-dirs',action='append',type=str,help='Set the directories that should be excluded from the inode dump, in regular expression (regexp) format (example: -e ".*/\.btrfs$" -e "^/home/user/tmp$"), NOTE: can be set multiple times for multiple exclusions if needed and this setting has effect only when the action is "dump" and will remain the same during the detect!')
    my_parser.add_argument('--one-file-system', action='store_true', required=False, help='Limit the dumping to happen within one filesystem / mount only, NOTE: this setting has effect only when the action is "dump" and will remain the same during the detect!')
    my_parser.add_argument('-i', '--input-dump-file', action='store', type=str, help='Set the input inode dump file (required when the action is "detect" and has no effect when the action is "dump")')
    my_parser.add_argument('-r', '--rename-script-rootdir', action='store', type=str, required=False, help='Rename the original root directory to something else in the detection output script, NOTE: this setting has effect only when the action is "detect" and has no effect when the action is "dump"!')
    my_parser.add_argument('-f', '--dir-exclusion-file-for-rsync', action='store', type=str, required=False, help='Set the output file for excluded dir list file for Rsync, NOTE: this setting has effect only when the action is "detect" and has no effect when the action is "dump"!')
    args = my_parser.parse_args()
    action = args.action
    rootdir = args.root_dir
    if action== 'dump' and rootdir == None:
        my_parser.error('-d / --root-dir argument is required when action is "dump"')
        quit()
    dumpfile = args.input_dump_file
    if action== 'detect' and dumpfile == None:
        my_parser.error('-i / --input-dump-file argument is required when action is "detect"')
        quit()
    outputfile = args.output
    if args.one_file_system:
        one_file_system_only = True
    else:
        one_file_system_only = False
    if args.excluded_dirs:
        edirsenabled=True
        excluded_dirs_regex = args.excluded_dirs
        cexcludeddirsregex = "(" + ")|(".join(excluded_dirs_regex) + ")"
    else:
        edirsenabled=False
    if args.rename_script_rootdir:
        replace_root_dir_of_final_script = args.rename_script_rootdir
    else:
        replace_root_dir_of_final_script = False
    if args.dir_exclusion_file_for_rsync:
        rsyncefile=args.dir_exclusion_file_for_rsync
    else:
        rsyncefile=False
    
    if action == 'dump':
        print('Starting to scan inodes of files and directories from: ' + rootdir + ' and writing the inode data to ' + outputfile)
        dump_inodes(rootdir, outputfile)
        print('Inode dump finished.')
    else:
        print('Starting to detect file and directory moves/renames by using inode dump file: ' + dumpfile + ' and writing the final script to ' + outputfile)
        tr = MovingTree(dumpfile)
        tr.create_script(outputfile)
        print('Detection finished.')

