#!/usr/bin/env bash

LINK="eth0"
CONTAINER=$1

set -eo pipefail

run_in_container() {
  docker run --network=host --privileged alpine "$@"
}

iflink=$(docker exec $CONTAINER cat /sys/class/net/$LINK/iflink)

devices=$(run_in_container ls /sys/class/net)
for device in $devices; do
  index=$(run_in_container cat /sys/class/net/$device/ifindex)
  if [ $index == $iflink ]; then
    echo $device
  fi
done
