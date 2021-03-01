#!/bin/bash
cores=$(grep -c ^processor /proc/cpuinfo)
for (( c=1;c<$cores;c++))
do
    echo $c
    taskset -c $c ./.libfuzzer_test.elf  2>/dev/null &
    sleep 0.1
done

