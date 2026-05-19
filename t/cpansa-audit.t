use 5.36.0;
use warnings;

use File::Temp qw(tempdir);
use JSON::MaybeXS qw(decode_json encode_json);
use Path::Tiny;
use Test::More;

my $tmpdir = path(tempdir(CLEANUP => 1));
my $cpansa = $tmpdir->child('cpansa.json');
$cpansa->spew_raw(encode_json({
  dists => {
    'DBD-SQLite' => {
      advisories => [
        {
          id => 'CPANSA-DBD-SQLite-2018-8740-sqlite',
          distribution => 'DBD-SQLite',
          affected_versions => ['>=1.00,<=1.02'],
          cves => ['CVE-2018-8740'],
          references => ['https://example.test/sqlite'],
          reported => '2018-03-17',
          description => 'sqlite fixture',
        },
        {
          id => 'CPANSA-DBD-SQLite-2018-8740-sqlite',
          distribution => 'DBD-SQLite',
          affected_versions => ['>=1.03,<=1.04'],
          cves => ['CVE-2018-8740'],
          references => ['https://example.test/sqlite'],
          reported => '2018-03-17',
          description => 'sqlite fixture',
        },
      ],
    },
  },
}));

my $tsv = `$^X bin/cpansec-feed-audit-cpansa --cpansa-json $cpansa`;
is($? >> 8, 0, 'audit script emits TSV');
like($tsv, qr/^distribution\tid\trows\taffected_version_count\tcves\tdiffering_fields\taffected_versions/m, 'TSV has header');
like($tsv, qr/DBD-SQLite\tCPANSA-DBD-SQLite-2018-8740-sqlite\t2\t2\tCVE-2018-8740\t\t>=1\.00,<=1\.02 \| >=1\.03,<=1\.04/, 'TSV describes repeated advisory');

my $json = `$^X bin/cpansec-feed-audit-cpansa --cpansa-json $cpansa --format json`;
is($? >> 8, 0, 'audit script emits JSON');
my $rows = decode_json($json);
is(scalar $rows->@*, 1, 'one repeated advisory group in JSON');
is($rows->[0]{rows}, 2, 'JSON includes row count');
is_deeply($rows->[0]{affected_versions}, ['>=1.00,<=1.02', '>=1.03,<=1.04'], 'JSON includes merged affected versions');
is_deeply($rows->[0]{differing_fields}, [], 'JSON flags no non-version field differences');

done_testing;
