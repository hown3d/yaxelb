#!/usr/bin/env bash

docker build -t krun .
container=$(docker create krun)

function copy() {
  path=$1
  dst=$path
  if [[ -n $2 ]]; then
    dst=$2
  fi
  if [ ! -f ${path} ]; then
    docker cp -L ${container}:${path} ${dst}
  fi
}

function copy_if_missing() {
  path=$1
  if [ ! -f ${path} ]; then
    copy "$@"
  fi
}

copy /usr/local/bin/krun
copy /usr/local/lib64/libkrun.so /usr/lib/aarch64-linux-gnu/libkrun.so.1
copy /usr/local/lib64/libkrunfw.so /usr/lib/aarch64-linux-gnu/libkrunfw.so.5
copy_if_missing /usr/lib/aarch64-linux-gnu/libyajl.so.2
copy_if_missing /usr/lib/aarch64-linux-gnu/libcap.so.2
