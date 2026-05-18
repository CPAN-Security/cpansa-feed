use 5.36.0;
use warnings;

use File::Temp qw(tempdir);
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

done_testing;
