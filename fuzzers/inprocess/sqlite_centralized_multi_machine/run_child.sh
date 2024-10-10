#!/bin/bash

./ossfuzz --cores 2-3 --input ./corpus --parent-addr 0.0.0.0:50000 --broker-port 3000
