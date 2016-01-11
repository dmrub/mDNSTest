#!/bin/bash

#LIBDIR=/usr/lib64
LIBDIR=$HOME/proj_de3/mDNS/Community-mdnsResponder/mdns-patched/mDNSPosix/build/prod

g++ -L$LIBDIR -ldns_sd -Wall client.cpp -oclient || exit 1
g++ -L$LIBDIR -ldns_sd -Wall testservice.cpp -otestservice || exit 1
gcc -L$LIBDIR -ldns_sd -Wall client2.c -oclient2 || exit 1

