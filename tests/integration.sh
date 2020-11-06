#!/bin/bash

trap "echo FAILED; exit 1" ERR

cp -H /bin/sleep /tmp

/tmp/sleep 60 &

rm -f /tmp/sleep

python3 restartable -v | grep -q sleep.60

kill %1

echo PASSED
