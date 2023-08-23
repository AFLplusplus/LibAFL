#!/bin/bash
PATH="/bin:/usr/bin"

IPCS_S=$(ipcs -s | grep -E "0x[0-9a-f]+ [0-9]+" | grep "${USER}" | cut -f2 -d" ")
IPCS_M=$(ipcs -m | grep -E "0x[0-9a-f]+ [0-9]+" | grep "${USER}" | cut -f2 -d" ")
IPCS_Q=$(ipcs -q | grep -E "0x[0-9a-f]+ [0-9]+" | grep "${USER}" | cut -f2 -d" ")

for id in $IPCS_M; do
  ipcrm -m "$id";
done

for id in $IPCS_S; do
  ipcrm -s "$id";
done

for id in $IPCS_Q; do
  ipcrm -q "$id";
done

