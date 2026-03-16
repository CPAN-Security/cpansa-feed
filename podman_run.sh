#!/usr/bin/env sh

podman run --rm -it -v "$PWD":/work -w /work cpansa-feed bash -lc "$1"
