#!/usr/bin/env sh
set -ex

if ! command -v cpm >/dev/null 2>&1; then
  if command -v cpanm >/dev/null 2>&1; then
    cpanm -n App::cpm
  else
    curl -fsSL https://raw.githubusercontent.com/skaji/cpm/main/cpm -o /usr/local/bin/cpm
    chmod +x /usr/local/bin/cpm
  fi
fi

## Normally, this is fine
##
# cpm install -g

## But we want the latest cpan-audit and update cpan-s-a repo so we're not
## depending on it being released on CPAN
##
cpm install -g --show-build-log-on-failure CPAN::Audit

# for util/generate
cpm install -g --show-build-log-on-failure YAML::Tiny Mojolicious

# for generate-cpansa-data.pl
cpm install -g --show-build-log-on-failure JSON::MaybeXS JSON::Schema::Modern Path::Tiny HTTP::Tiny CPAN::Audit::DB Test::CVE

if [ ! -d cvelistV5/.git ]; then
  git clone --depth 1 --single-branch https://github.com/CVEProject/cvelistV5.git cvelistV5
else
  git -C cvelistV5 pull --ff-only
fi
