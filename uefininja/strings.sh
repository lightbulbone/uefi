#!/bin/bash

for f in $(find . -iname "$1")
do
    strings -a -f $f        # C-style strings
    strings -a -f -e l $f   # 16 bit LE strings
done
