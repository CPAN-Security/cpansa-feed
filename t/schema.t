use 5.36.0;
use warnings;

use JSON::MaybeXS qw(decode_json);
use JSON::Schema::Modern;
use Path::Tiny;
use Test::More;

my $schema = decode_json(path('schema.json')->slurp_raw);
my $validator = JSON::Schema::Modern->new(validate_formats => 1);
$validator->add_schema($schema);

my $feed = {
  'Example-Dist' => [
    {
      affected_versions => ['=1.00'],
      distribution => 'Example-Dist',
      version_range => ['=1.00'],
      affected_releases => [],
      severity => 'low',
    },
  ],
};

my $result = $validator->evaluate($schema->{'$id'}, $feed);
ok($result->valid, 'schema accepts low severity');

done_testing;
