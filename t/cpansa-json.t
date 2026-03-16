use 5.36.0;
use warnings;

use Test::More;

use lib 'lib';
use CPANSec::Feed::CPANSA qw(latest_release_url load_database);

is(
  latest_release_url(),
  'https://github.com/briandfoy/cpan-security-advisory/releases/latest/download/cpan-security-advisory.json',
  'uses GitHub latest release asset URL',
);

my $db = load_database('t/data/cpansa-loader-fixture.json');
is(ref($db), 'HASH', 'database loaded');
is(ref($db->{dists}), 'HASH', 'database has dists');
is($db->{dists}{'JSON-XS'}{advisories}[0]{id}, 'CPANSA-JSON-XS-2025-40928', 'advisory preserved');

done_testing;
