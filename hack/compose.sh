#!/usr/bin/env bash

function run_ethtool() {
  docker run --network=host --privileged -v /sys:/sys nicolaka/netshoot ethtool -K "$("$DIR"/tools/veth-of-container.sh yaxelb-lb-1)" "$@"
}

set -eo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && /bin/pwd)"

docker compose "$1" --build --detach

# configure veth to support XDP_REDIRECT
run_ethtool gro on
run_ethtool tx-checksumming off

docker compose logs -f
