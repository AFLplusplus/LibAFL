#!/usr/bin/env python3

import os
import sys
import subprocess

EXCLUDE_LIST = ('AFLplusplus', 'target')

old_ver = sys.argv[1]
new_ver = sys.argv[2]

result = subprocess.run("git config --file .gitmodules --get-regexp path | awk '{ print $2 }'", shell=True, stdout=subprocess.PIPE)
submodules = filter(lambda x: len(x) > 0, result.stdout.decode('utf-8').split('\n'))

for subdir, dirs, files in os.walk(os.getcwd()):
    exclude = False
    for word in EXCLUDE_LIST:
        if word in subdir.split(os.sep):
            exclude = True
            break
    for sub in submodules:
        if subdir.startswith(sub):
            exclude = True
            break
    if exclude:
        continue

    for file in files:
        if file != 'Cargo.toml':
            continue
        fname = os.path.join(subdir, file)
        print(fname)
        
        with open(fname, 'r') as f:
            toml = f.read()
        lines = toml.split('\n')
        
        for i in range(len(lines)):
            if lines[i].startswith('version = "%s"' % old_ver):
                lines[i] = 'version = "%s"' % new_ver
            if (lines[i].startswith('libafl') or '_libafl' in lines[i]) and 'version="%s"' % old_ver in lines[i].replace('= ', '=').replace(' =', '='):
                lines[i] = lines[i].replace('version = "%s"' % old_ver, 'version = "%s"' % new_ver)
                lines[i] = lines[i].replace('version= "%s"' % old_ver, 'version = "%s"' % new_ver)
                lines[i] = lines[i].replace('version ="%s"' % old_ver, 'version = "%s"' % new_ver)
                lines[i] = lines[i].replace('version="%s"' % old_ver, 'version = "%s"' % new_ver)
        
        with open(fname, 'w') as f:
            f.write('\n'.join(lines))
