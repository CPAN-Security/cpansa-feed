use 5.36.0;
use warnings;

use JSON::MaybeXS qw(decode_json);
use Path::Tiny;
use Test::More;
use version;

use lib 'lib';
use CPANSA::Feed::VersionRange qw(releases_in_range split_version_range);

my $fixtures = decode_json(path('t/data/version-range-fixtures.json')->slurp_raw);

foreach my $fixture ($fixtures->@*) {
  subtest $fixture->{name} => sub {
    my $clauses = split_version_range('fixture', $fixture->{affected_versions});
    my @versions = map {
      +{
        release => $_->{release},
        version => version->parse($_->{version_numified}),
      }
    } $fixture->{releases}->@*;

    my $actual = releases_in_range(\@versions, $clauses);
    is_deeply($actual, $fixture->{expected_releases}, 'matched expected release set');
  };
}

done_testing;
