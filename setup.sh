#!/usr/bin/env sh
set -ex

## Normally, this is fine
##
# cpm install -g

## But we want the latest cpan-audit and update cpan-s-a repo so we're not
## depending on it being released on CPAN
##
cpanm -n --installdeps CPAN::Audit

# for util/generate
cpanm -n YAML::Tiny Mojolicious

# for generate-cpansa-data.pl
cpanm -n JSON::MaybeXS JSON::Schema::Modern Path::Tiny HTTP::Tiny CPAN::Audit::DB;

git clone --depth 1 --single-branch https://github.com/CVEProject/cvelistV5.git cvelistV5