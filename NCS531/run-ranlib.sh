#!/bin/sh

SECONDS=0
while [ 1 ]
do
    duration=$SECONDS
    min=$(($duration / 60))
    sec=$(($duration % 60))
    echo "$min minutes and $sec seconds elapsed."
    ./retlib
done


