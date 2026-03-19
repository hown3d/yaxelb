#!/usr/bin/env bash
set -eo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && /bin/pwd)"

if ! docker image ls | grep xdp-dump &>/dev/null; then
  docker build -t xdp-dump -f ${DIR}/Dockerfile.xdpdump ${DIR}
fi

container=""

print_help() {
  echo "xdpdump.sh"
  echo "--container (binds xdpdump into other container network)"
}

REMAINING_ARGS=()

parse_flags() {
  while test $# -gt 0; do
    case "$1" in
    --container)
      container="${2}"
      shift 2
      ;;
    help)
      print_help
      exit 1
      ;;
    *)
      # Catch-all: If it's not a recognized flag, add it to our array
      REMAINING_ARGS+=("$1")
      shift
      ;;
    esac
  done
}

parse_flags "$@"

# 2. Overwrite the main script's $@ with the filtered array
set -- "${REMAINING_ARGS[@]}"

docker_network_flags=(
  "--net=host"
)

if [[ -n $container ]]; then
  docker_network_flags=(
    "--net=container:$container"
    "--pid=container:$container"
  )
fi

docker run -iq --rm \
  --privileged \
  "${docker_network_flags}" \
  --cap-add=ALL \
  --volume /lib/modules:/lib/modules:ro \
  --volume /sys:/sys \
  --volume $(pwd):/work \
  xdp-dump \
  "$@"
# -w - | docker run -i nicolaka/netshoot tcpdump -n -vvv -r -
