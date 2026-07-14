#!/usr/bin/env bash

function run_ethtool() {
  docker run --network=host --privileged -v /sys:/sys nicolaka/netshoot ethtool -K "$@"
}

set -eo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && /bin/pwd)"

docker compose "$1" --build --detach

veth="$("$DIR"/tools/veth-of-container.sh yaxelb-lb-1)"
echo "configure $veth to support XDP_REDIRECT"
run_ethtool "$veth" gro on
run_ethtool "$veth" tx-checksumming off

docker compose logs -f
