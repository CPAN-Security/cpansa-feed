package CPANSA::Feed::VersionRange;

use 5.36.0;
use warnings;

use Exporter qw(import);
use List::Util qw(any);
use version;

our @EXPORT_OK = qw(split_version_range version_in_range releases_in_range);

sub split_version_range ($dist, $version_range) {
  my @clauses;
  foreach my $entry ($version_range->@*) {
    my (@greater, @lower, @equal, @not_equal);
    foreach my $expr (split /\s*,\s*/, $entry) {
      if ($expr =~ /\A\s*([>=<!]=?)?\s*([0-9]\S*)\s*\z/) {
        my ($op, $ver) = ($1, $2);
        $ver = version->parse($ver);
        if ($op eq '>') {
          push @greater, $ver;
        }
        elsif ($op eq '>=') {
          push @greater, $ver;
          push @equal, $ver;
        }
        elsif ($op eq '<') {
          push @lower, $ver;
        }
        elsif ($op eq '<=') {
          push @lower, $ver;
          push @equal, $ver;
        }
        elsif ($op eq '!=') {
          push @not_equal, $ver;
        }
        elsif ($op eq '=') {
          push @equal, $ver;
        }
        else {
          die "unknown operator '$op' in '$expr'";
        }
      }
      else {
        die "unknown version range '$expr'";
      }
    }
    push @clauses, {
      greater => \@greater,
      lower => \@lower,
      equal => \@equal,
      not_equal => \@not_equal,
    };
  }
  return \@clauses;
}

sub version_in_range ($version, $clauses) {
  return 0 if ref($clauses) ne 'ARRAY' || !$clauses->@*;
  return any { _version_in_clause($version, $_) } $clauses->@*;
}

sub releases_in_range ($versions, $clauses) {
  my @releases_in_range;
  my %seen_release;
  foreach my $version ($versions->@*) {
    next if !version_in_range($version->{version}, $clauses);
    next if $seen_release{$version->{release}}++;
    push @releases_in_range, $version->{release};
  }
  return [sort @releases_in_range];
}

sub _version_in_clause ($version, $range) {
  return 0 if any { $version == $_ } $range->{not_equal}->@*;
  return 1 if any { $version == $_ } $range->{equal}->@*;

  my @greater = sort $range->{greater}->@*;
  my @lower = sort $range->{lower}->@*;

  return 1 if @greater && !@lower && $version > $greater[-1];
  return 1 if @lower && !@greater && $version < $lower[0];
  return 1 if @greater && @lower && $version > $greater[-1] && $version < $lower[0];
  return 0;
}

1;
