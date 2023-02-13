#!/bin/bash
if [ "$1" == "" ] 
then
    echo "please insert a valid ip route (network must be /24)"
    echo "example ./ip_discover.sh 192.168.1"
else
    for i in `seq 1 254`; 
        do
            ping -c 1 $1.$i | grep "64 bytes" | cut -d " " -f 4 | tr -d ":" &
        done
fi