#!/usr/bin/env bash
set -eo pipefail

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
  "--pid=host"
  "--net=host"
)

if [[ -n $container ]]; then
  docker_network_flags=(
    "--net=container:$container"
    "--pid=container:$container"
  )
fi

if command -v pwru; then
  pwru "$@"
else
  if ! docker image ls | grep pwru; then
    docker build -t pwru https://github.com/cilium/pwru.git
  fi
  docker run --privileged -t "$docker_network_flags" -v /sys/kernel:/sys/kernel --rm --entrypoint=pwru pwru "$@"
fi
