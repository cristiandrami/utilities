#!/bin/bash 
if [ "$1" == "" ] 
then
    echo "you have to put a file name as first argument"
    echo "example ./nmap_ips ips.txt"
else
for ip in $(cat $1); 
    do
        nmap $ip &
    done
fi