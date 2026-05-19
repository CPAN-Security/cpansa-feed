use 5.36.0;
use warnings;

use File::Temp qw(tempdir);
use JSON::MaybeXS qw(encode_json);
use Path::Tiny;
use Test::More;

use lib 'lib';
use CPANSec::Feed::Generator qw(generate_feed);

my $tmpdir = path(tempdir(CLEANUP => 1));
$tmpdir->child('cves')->mkpath;

my $db = {
  dists => {
    'Example-Dist' => {
      advisories => [
        {
          id => 'CPANSA-Example-Dist-2026-0001',
          distribution => 'Example-Dist',
          affected_versions => [],
          cves => [],
          references => [],
          reported => '2026-04-04',
          severity => 'low',
          description => 'fixture advisory with no affected versions',
        },
      ],
    },
  },
};

my ($feed, $rows) = generate_feed(
  cpansa_db => $db,
  cve_dir => $tmpdir,
);

is_deeply($feed, {}, 'CPANSA advisory with empty affected_versions is not emitted');
is(scalar $rows->@*, 1, 'one report row produced');
is($rows->[0]{status}, 'skipped', 'advisory is reported as skipped');
is($rows->[0]{determination}, 'cpansa missing usable versions', 'skip reason is explicit');
is($rows->[0]{note}, 'No usable affected versions in CPANSA advisory', 'note explains missing versions');

my $cve = {
  dataType => 'CVE_RECORD',
  dataVersion => '5.1',
  cveMetadata => {
    cveId => 'CVE-2026-46719',
    assignerShortName => 'CPANSec',
    datePublished => '2026-05-16T00:00:00.000Z',
    dateUpdated => '2026-05-16T00:00:00.000Z',
    state => 'PUBLISHED',
  },
  containers => {
    cna => {
      providerMetadata => {
        shortName => 'CPANSec',
      },
      affected => [
        {
          packageName => 'Net-Statsd-Lite',
          versions => [
            {
              status => 'affected',
              version => '0',
              lessThan => '0.9.0',
            },
          ],
        },
      ],
      descriptions => [
        {
          lang => 'en',
          value => 'Net::Statsd::Lite versions before 0.9.0 for Perl allowed metric injections',
        },
      ],
      references => [
        {
          url => 'https://example.test/CVE-2026-46719',
        },
      ],
    },
  },
};

my $cve_dir = $tmpdir->child('cpansec-cves');
$cve_dir->child('cves', '2026', '467xx')->mkpath;
$cve_dir->child('cves', '2026', '467xx', 'CVE-2026-46719.json')->spew_raw(encode_json($cve));

my $cache_dir = $tmpdir->child('metacpan-cache');
$cache_dir->mkpath;
$cache_dir->child(unpack('H*', 'Net-Statsd-Lite') . '.json')->spew_raw(encode_json([
  {
    release => 'CPANSEC/Net-Statsd-Lite-0.8.0',
    version_numified => '0.8.0',
  },
]));

my ($cve_feed) = generate_feed(
  cpansa_db => { dists => {} },
  cve_dir => $cve_dir,
  metacpan_cache_dir => $cache_dir,
  metacpan_cache_ttl => 0,
);

my $record = $cve_feed->{'Net-Statsd-Lite'}[0];
ok($record, 'CPANSec CVE record was emitted');
ok(!exists $record->{severity}, 'missing CVSS severity is omitted');
is($record->{distribution}, 'Net-Statsd-Lite', 'distribution key remains aligned');
is_deeply($record->{version_range}, ['<0.9.0'], 'version_range key remains aligned');
is_deeply($record->{affected_releases}, ['CPANSEC/Net-Statsd-Lite-0.8.0'], 'affected_releases key remains aligned');
is($record->{cve_id}, 'CVE-2026-46719', 'cve_id key remains aligned');
ok(!grep { /^ARRAY\(/ || /^HASH\(/ } keys $record->%*, 'record has no stringified reference keys');

my $merge_cache_dir = $tmpdir->child('merge-metacpan-cache');
$merge_cache_dir->mkpath;
$merge_cache_dir->child(unpack('H*', 'DBD-SQLite') . '.json')->spew_raw(encode_json([
  {
    release => 'ISHIGAKI/DBD-SQLite-1.01',
    version_numified => '1.01',
  },
  {
    release => 'ISHIGAKI/DBD-SQLite-1.03',
    version_numified => '1.03',
  },
]));

my ($merged_feed, $merged_rows) = generate_feed(
  cpansa_db => {
    dists => {
      'DBD-SQLite' => {
        advisories => [
          {
            id => 'CPANSA-DBD-SQLite-2018-8740-sqlite',
            distribution => 'DBD-SQLite',
            affected_versions => ['>=1.00,<=1.02'],
            cves => [],
            references => ['https://example.test/sqlite'],
            reported => '2018-03-17',
            description => 'sqlite fixture',
          },
          {
            id => 'CPANSA-DBD-SQLite-2018-8740-sqlite',
            distribution => 'DBD-SQLite',
            affected_versions => ['>=1.03,<=1.04'],
            cves => [],
            references => ['https://example.test/sqlite'],
            reported => '2018-03-17',
            description => 'sqlite fixture',
          },
        ],
      },
    },
  },
  cve_dir => $tmpdir,
  metacpan_cache_dir => $merge_cache_dir,
  metacpan_cache_ttl => 0,
);

my $merged_record = $merged_feed->{'DBD-SQLite'}[0];
is(scalar $merged_feed->{'DBD-SQLite'}->@*, 1, 'same CPANSA id rows are merged into one record');
is_deeply(
  $merged_record->{affected_versions},
  ['>=1.00,<=1.02', '>=1.03,<=1.04'],
  'affected_versions are merged',
);
is_deeply(
  $merged_record->{affected_releases},
  ['ISHIGAKI/DBD-SQLite-1.01', 'ISHIGAKI/DBD-SQLite-1.03'],
  'affected releases are resolved from merged ranges',
);
like($merged_rows->[0]{note}, qr/merged 2 CPANSA rows into 2 affected version ranges/, 'report row notes merged source rows');

my ($authoritative_feed) = generate_feed(
  cpansa_db => {
    dists => {
      'Net-Statsd-Lite' => {
        advisories => [
          {
            id => 'CPANSA-Net-Statsd-Lite-2026-46719-vendored',
            distribution => 'Net-Statsd-Lite',
            affected_versions => ['>=100,<=200'],
            cves => ['CVE-2026-46719'],
            references => ['https://example.test/vendored'],
            reported => '2026-05-16',
            description => 'vendored fixture',
          },
          {
            id => 'CPANSA-Net-Statsd-Lite-2026-46719-vendored',
            distribution => 'Net-Statsd-Lite',
            affected_versions => ['>=201,<=202'],
            cves => ['CVE-2026-46719'],
            references => ['https://example.test/vendored'],
            reported => '2026-05-16',
            description => 'vendored fixture',
          },
        ],
      },
    },
  },
  cve_dir => $cve_dir,
  metacpan_cache_dir => $cache_dir,
  metacpan_cache_ttl => 0,
);

my $authoritative_record = $authoritative_feed->{'Net-Statsd-Lite'}[0];
is_deeply($authoritative_record->{affected_versions}, ['<0.9.0'], 'CPANSec CVE affected_versions stay authoritative');
is_deeply($authoritative_record->{affected_releases}, ['CPANSEC/Net-Statsd-Lite-0.8.0'], 'CPANSec CVE affected_releases stay authoritative');
is($authoritative_record->{cpansa_id}, 'CPANSA-Net-Statsd-Lite-2026-46719-vendored', 'CPANSA still enriches the CPANSec record with an advisory id');

done_testing;
