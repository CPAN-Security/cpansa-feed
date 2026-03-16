#!/usr/bin/env sh
set -eu

image=${1:-cpansec-feed-deb}
repo_dir=${PWD}
parent_dir=$(dirname "$repo_dir")
repo_name=$(basename "$repo_dir")

podman build -t "$image" "$repo_dir"
podman run --rm -v "$parent_dir":/src -w "/src/$repo_name" "$image" bash -lc 'dpkg-buildpackage -us -uc'
