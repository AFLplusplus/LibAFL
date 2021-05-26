#!/bin/sh

sudo sysctl -w kern.sysv.shmmax=524288000
sudo sysctl -w kern.sysv.shmmin=1
sudo sysctl -w kern.sysv.shmmni=64
sudo sysctl -w kern.sysv.shmseg=16
sudo sysctl -w kern.sysv.semmns=130
sudo sysctl -w kern.sysv.shmall=131072000
sudo sysctl -w kern.sysv.maxproc=2048
sudo sysctl -w kern.maxprocperuid=512
