#!/usr/bin/env sh
set -eu

image=${CPANSEC_FEED_IMAGE:-cpansec-feed-deb}
if [ -t 0 ] && [ -t 1 ]; then
  exec podman run --rm -it -v "$PWD":/work -w /work "$image" bash -lc "$1"
fi

exec podman run --rm -v "$PWD":/work -w /work "$image" bash -lc "$1"
