#!/bin/bash

LINUX_MODULES=$(pacman -Ql linux-headers | grep -m 1 -E '/usr/lib/modules/[^/]*/' | sed 's|.*/usr/lib/modules/\([^/]*\)/.*|\1|')
export LINUX_MODULES

# Default root password
echo "root:toor" | chpasswd

cd /setup

. ./api.sh

find "/lib/modules/$LINUX_MODULES/build" -name "*.h" | grep stdarg
find "/lib/modules/$LINUX_MODULES/build" -name "*.h" | grep stdout

make clean
make -j all