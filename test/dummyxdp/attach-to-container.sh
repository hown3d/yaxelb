#!/usr/bin/env bash
DIR=$(dirname "$0")
containers=("$@")

function run_command() {
  docker_network_flags=(
    "--net=container:$container"
    "--pid=container:$container"
  )

  ifindex=$(docker run $docker_network_flags \
    --privileged \
    nicolaka/netshoot cat /sys/class/net/eth0/iflink)

  vethname=$(docker run --network=host nicolaka/netshoot ip -j link show | jq -r '.[] | select(.ifindex=='$ifindex') | .ifname')
  echo "veth pair of $container: $vethname"
  command="ip link set dev ${vethname} $@"
  echo "[$container]: $command"
  docker run --network=host \
    -v $DIR:/work -w /work \
    --privileged nicolaka/netshoot ${command}
}

for container in "${containers[@]}"; do
  run_command xdpgeneric off
  run_command xdp obj dummy_bpfel.o sec xdp
done
