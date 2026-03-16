#!/usr/bin/env sh
set -eu

mkdir -p _site var

perl -Ilib -MCPANSec::Feed::FileUtil=write_if_changed -MPath::Tiny=path -e '
  write_if_changed("_site/schema.json", path("schema.json")->slurp_raw, raw => 1);
  write_if_changed("_site/cpansa_dev.json", path("cpansa_dev.json")->slurp_raw, raw => 1);
  write_if_changed("_site/index.html", q{<h1>cpansa-feed</h1><a href="cpansa.json">cpansa.json</a><br><a href="report.html">validation report</a>});
'

perl -Ilib bin/cpansec-feed-generate \
  --cpansa-json var/cpan-security-advisory.json \
  --cvelist-dir cvelistV5 \
  --schema-path schema.json \
  --metacpan-cache-dir var/metacpan-cache \
  --report-html _site/report.html \
  --output _site/cpansa.json \
  > /dev/null
