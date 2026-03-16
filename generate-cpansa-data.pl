#!/usr/bin/env perl
use 5.36.0;
use warnings;

use FindBin qw($Bin);
use lib "$Bin/lib";

use CPANSec::Feed::CPANSA qw(load_database);
use CPANSec::Feed::Generator qw(write_feed_json);

my $cpansa_json = $ENV{CPANSA_JSON} // 'var/cpan-security-advisory.json';
my $cvelist_dir = $ENV{CVELIST_DIR} // 'cvelistV5';
my $schema_path = $ENV{CPANSA_SCHEMA} // 'schema.json';
my $report_html = $ENV{CPANSA_REPORT_HTML};
my $metacpan_cache_dir = $ENV{METACPAN_CACHE_DIR} // 'var/metacpan-cache';

my $db = load_database($cpansa_json);
my $json = write_feed_json(
  cpansa_db => $db,
  cve_dir => $cvelist_dir,
  schema_path => $schema_path,
  report_html => $report_html,
  metacpan_cache_dir => $metacpan_cache_dir,
);

binmode(STDOUT, ':encoding(UTF-8)');
print $json;
