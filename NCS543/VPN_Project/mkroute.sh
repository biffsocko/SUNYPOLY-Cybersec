#!/bin/sh
#################################################
# Tom Murphy
# mkroute.sh
#
# this creates the needed route for the remote server
# in this demonstration
#################################################

route add -net 10.4.2.0/24 gw 192.168.1.66  enp0s8
