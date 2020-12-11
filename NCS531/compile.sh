#!/bin/sh
#######################################################
# Tom Murphy
# compile
#
# compiles c programs with The StackGuard Protection 
# Scheme turned off
#
# usage: compile Foo.c
#######################################################

usage(){
    echo "USAGE: $0 <source.c>"
    exit 1
}

if [ -z $1 ]
then
     usage
fi

if [ ! -f $1 ]
then
    echo "$1 - no such file exists"
    usage
fi

ls $1 | grep ".c" > /dev/null 2>&1
if [ $? -ne 0 ]
then
    echo "file extension does not indicate c source file .. exiting"
    usage
fi


NAME=`echo $1 | awk -F "." '{print $1}'`


gcc -march=native -o ${NAME} $1

