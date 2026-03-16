#!/usr/bin/env sh
set -ex
mkdir -p _site
cp -p schema.json _site/schema.json
cp -p cpansa_dev.json _site/cpansa_dev.json

now=$(date)
echo "<h1>cpansa-feed updated $now</h1><a href=cpansa.json>cpansa.json</a><br><a href=report.html>validation report</a>" > _site/index.html

CPANSA_REPORT_HTML=_site/report.html perl generate-cpansa-data.pl > _site/cpansa.json
