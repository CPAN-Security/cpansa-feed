package CPANSA::Feed::VersionRange;

use 5.36.0;
use warnings;

use CPANSec::Feed::VersionRange qw(split_version_range version_in_range releases_in_range);
use Exporter qw(import);

our @EXPORT_OK = qw(split_version_range version_in_range releases_in_range);

1;
