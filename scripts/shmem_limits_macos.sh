#!/bin/sh

sudo sysctl -w kern.sysv.shmmax=524288000
sudo sysctl -w kern.sysv.shmmin=1
sudo sysctl -w kern.sysv.shmseg=16
sudo sysctl -w kern.sysv.shmall=131072000
sudo sysctl -w kern.maxprocperuid=512
