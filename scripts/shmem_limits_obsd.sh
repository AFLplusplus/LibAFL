#!/bin/sh
doas sysctl kern.shminfo.shmmax=536870912
doas sysctl kern.shminfo.shmmin=1
doas sysctl kern.shminfo.shmall=131072000
