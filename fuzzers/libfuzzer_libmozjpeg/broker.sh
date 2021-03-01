#!/bin/bash
taskset -c 0 ./.libfuzzer_test.elf

