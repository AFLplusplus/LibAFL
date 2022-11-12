#!/bin/sh

# shellcheck disable=SC2016
echo "Warning: this script is not a proper fix to do LLMP fuzzing." \
     'Instead, run `afl-persistent-config` with SIP disabled.'

sudo sysctl -w kern.sysv.shmmax=524288000
sudo sysctl -w kern.sysv.shmmin=1
sudo sysctl -w kern.sysv.shmseg=32
sudo sysctl -w kern.sysv.shmall=131072000
sudo sysctl -w kern.maxprocperuid=512
