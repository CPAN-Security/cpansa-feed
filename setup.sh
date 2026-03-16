#!/usr/bin/env sh
set -eu

mkdir -p var
perl -Ilib bin/cpansec-feed-update-data \
  --cpansa-json var/cpan-security-advisory.json \
  --cvelist-dir cvelistV5
