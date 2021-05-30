#!/bin/sh
sudo sysctl -a kern.ipc.shmmax=536870912
sudo sysctl -a kern.ipc.shmmin=1
sudo sysctl -a kern.ipc.shmall=131072000
