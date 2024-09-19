#!/bin/bash

# creates a symbolic link from bin-x.x to bin
# This just strips off last 3 characters when creating a link

LLVMFILES="/usr/bin/llvm*"
CLANGFILES="/usr/bin/clang*"
LLC=/usr/bin/llc-$1
OPT=/usr/bin/opt-$1
LLD=/usr/bin/lld-$1

for f in $LLVMFILES $CLANGFILES $LLC $OPT $LLD
do
	link=${f::-3}
	echo "linking" "$f" "to" "$link"
	ln -s "$f" "$link"
	if [ -e "$f" ]
	  then cp "$link" /usr/local/bin/
	fi
done
