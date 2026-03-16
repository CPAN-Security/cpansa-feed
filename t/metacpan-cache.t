use 5.36.0;
use warnings;

use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny;
use JSON::MaybeXS qw(encode_json);

use lib 'lib';
use CPANSec::Feed::Generator qw(load_metacpan_cache_file metacpan_cache_is_stale);

my $tmpdir = path(tempdir(CLEANUP => 1));
my $cache = $tmpdir->child('dist.json');
$cache->spew_raw(encode_json([
  {
    release => 'AUTHOR/Dist-1.23',
    version_numified => '1.23',
  },
]));

ok(!metacpan_cache_is_stale($cache, 6 * 60 * 60), 'fresh cache is not stale');

my $fresh = load_metacpan_cache_file($cache, ttl => 6 * 60 * 60);
is(ref($fresh), 'ARRAY', 'fresh cache loads');
is($fresh->[0]{release}, 'AUTHOR/Dist-1.23', 'fresh cache preserves release');
is($fresh->[0]{version_numified}, '1.23', 'fresh cache preserves version');

utime(time - (7 * 60 * 60), time - (7 * 60 * 60), $cache->stringify);

ok(metacpan_cache_is_stale($cache, 6 * 60 * 60), 'cache older than 6 hours is stale');
is(load_metacpan_cache_file($cache, ttl => 6 * 60 * 60), undef, 'stale cache is ignored');

ok(!metacpan_cache_is_stale($cache, 0), 'ttl 0 disables staleness checks');
my $ttl_disabled = load_metacpan_cache_file($cache, ttl => 0);
is(ref($ttl_disabled), 'ARRAY', 'stale cache loads when ttl is disabled');

done_testing;
