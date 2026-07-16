#!/usr/bin/env bash

set -eo pipefail

if ! docker image ls | grep compile; then
  docker buildx build -o type=image -t compile --target compile -f Dockerfile.bpf .
fi
