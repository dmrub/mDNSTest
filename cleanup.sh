#!/bin/bash

[ -z "$1" ] && echo "No file specified" && exit 1

tr "\315" ";" < "$1" > _tmp_ && \
    tr -d "\276" < _tmp_ > _tmp1_ && \
    mv _tmp1_ "$1" && \
    rm _tmp_

