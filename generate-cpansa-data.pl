use 5.36.0;
use warnings;
use version;

use JSON::Schema::Modern;
use JSON::MaybeXS;
use Path::Tiny;
use CPAN::Audit::DB;
use List::Util qw( any all );
use Digest::SHA qw(sha1_hex);
use HTTP::Tiny;
use Try::Tiny;

run();
exit;

sub run {
  my $cve_path = path('cvelistV5', 'cves');
  die 'unable to find base cve dir. Did you forget to setup?' if !$cve_path->is_dir;

  my $feed = {};
  my $db = CPAN::Audit::DB->db();
  foreach my $dist (sort keys $db->{dists}->%*) {
    foreach my $report ($db->{dists}{$dist}{advisories}->@*) {
      last if $report->{darkpan} && $report->{darkpan} eq 'true';

      # make some weird values compliant with our schema
      _apply_hotfixes($report, $dist) or next;
      my $cve = _find_cve($cve_path, $report->{cve_id});

      push $feed->{$dist}->@*, {
        # legacy (purely for Test::CVE support)
        cpansa_id         => $report->{id},
        affected_versions => $report->{affected_versions},
        cves              => $report->{cves},
        description       => $report->{description},
        reported          => $report->{reported},
        severity          => $report->{severity},

        # new
        distribution      => $dist,
        version_range     => $report->{affected_versions},
        affected_releases => _get_versions_from_range($dist, $report->{affected_versions}),
        cve_id            => $report->{cve_id},
        cve               => $cve,
        title             => _fetch_title($cve) // $report->{description},
        references        => $report->{references},
      };
    }
  }

  my $json = JSON::MaybeXS->new(canonical => 1);
  my $js = JSON::Schema::Modern->new(validate_formats => 1);
  my $schema = $json->decode(path("schema.json")->slurp_raw);
  my $schema_id = $schema->{'$id'};
  $js->add_schema($schema);

  my $result = $js->evaluate($schema_id, $feed);

  if ($result->valid) {
    binmode(STDOUT, ":encoding(UTF-8)");
    print $json->encode($feed);
  }
  else {
    die $json->encode($result) . "\n[^] output does not conform to schema";
  }
}

sub _fetch_title ($cve) {
    return unless $cve && ref $cve;
    return $cve->{containers}{cna}{title};
}

sub _find_cve ($cve_path, $cve_id) {
    return unless $cve_id;
    return unless $cve_id =~ /\ACVE-/;
    my (undef, $year, $n) = split '-', $cve_id;
    my $n_len = length($n);
    my $complete_path;
    while ($n_len > 0) {
        my $dir = substr($n, 0, $n_len) . ('x' x (length($n) - $n_len)); $n_len--;
        $complete_path = $cve_path->child($year, $dir, $cve_id . '.json');
        if ($complete_path->is_file) {
            last;
        }
        else {
            $complete_path = undef;
        }
    }
    unless ($complete_path) {
        warn "unable to find $cve_id in cvelistV5. Skipping CVE data.";
        return;
    }
    return decode_json($complete_path->slurp_raw);
}

sub _get_versions_from_range ($distname, $version_range) {
    my $ranges = split_version_range ($distname,$version_range);
    my $response = decode_json(
        HTTP::Tiny->new->post('https://fastapi.metacpan.org/release?size=5000', {
            content => encode_json({
                query  => { term => { distribution => $distname } },
                fields => ['version', 'version_numified', 'author']
            })
        })->{content}
    );
    my @all_versions;
    foreach my $entry ($response->{hits}{hits}->@*) {
        push @all_versions, {
            release => $entry->{fields}{author} . '/' . $distname . '-' . $entry->{fields}{version},
            version => version->parse($entry->{fields}{version_numified})
        };
    }

    my @releases_in_range;
    foreach my $version (@all_versions) {
        push @releases_in_range, $version->{release} if version_in_range($version->{version}, $ranges);
    }
    return [sort @releases_in_range];
}

sub version_in_range ($version, $range) {
    return 1 if List::Util::any { $version == $_ } $range->{equal}->@*;
    return 1 if List::Util::any { $version == $_ } $range->{not_equal}->@*;
    my @greater = sort $range->{greater}->@*;
    my @lower   = sort $range->{lower}->@*;
    return 1 if @greater && (!@lower || $greater[-1] > $lower[-1]) && $version > $greater[-1];
    return 1 if @lower && (!@greater || ($lower[0] < $greater[0])) && $version < $lower[0];
    return 1 if (( List::Util::any { $version >  $_ } $range->{greater}->@*)
                    && (List::Util::any { $version <  $_ } $range->{lower}->@*));
    return 0;
}

sub split_version_range ($dist, $version_range) {
    my (@greater, @lower, @equal, @not_equal);
    foreach my $entry ($version_range->@*) {
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
    }
    return { greater => \@greater, lower => \@lower, equal => \@equal, not_equal => \@not_equal };
}

# return true if all is well, false if report should be skipped.
sub _apply_hotfixes ($report, $dist) {
  return unless defined $report->{affected_versions};
  return unless defined $report->{distribution};

  if ($report->{distribution} ne $dist) {
      warn "$report->{id} has mixed dists: $report->{distribution} and $dist";
      return;
  }

  # (silently) convert mixed data so they are always arrayrefs.
  foreach my $k (qw(cves references affected_versions)) {
    if (!ref $report->{$k}) {
      if (!defined $report->{$k} || $report->{$k} eq '') {
        $report->{$k} = [];
      }
      else {
        $report->{$k} = [$report->{$k}];
      }
    }
  }

  # we can't continue unless we know the affected_versions.
  if (!all { defined } $report->{affected_versions}->@*) {
    warn "$report->{id} has undefined values in $report->{affected_versions}. Skipping.";
    return;
  }

  if ($report->{cves}->@* > 1) {
      warn "$report->{id} has more than one CVE associated with it";
      $report->{cves} = [$report->{cves}[0]];
  }
  $report->{cve_id} = $report->{cves}[0];

  # now that we have affected_versions as an arrayref,
  # we go through it and sanitize its elements.
  my @sanitized_versions;
  foreach my $version ($report->{affected_versions}->@*) {
    my @raw_ands = split /,/ => $version;
    my @sanitized_ands;
    foreach my $and (@raw_ands) {
      # drop leading spaces.
      if ($and =~ /\A\s+/) {
        warn "$report->{id} has leading spaces in version '$and'! fixing";
        $and =~ s/\A\s+//;
      }

      # forces mandatory symbol before number.
      if ($and =~ /\A(>=?|<=?|=)\d/) {
        push @sanitized_ands, $and; # all is well with the world;
      }
      else {
        if ($and =~ /\A\d/) {
          warn "$report->{id} affected_versions should always provide a sign before the number in: '$version'. Assuming '='";
          push @sanitized_ands, "=$and";
          next;
        }
        # convert "==" to "=".
        elsif ($and =~ /\A==\d/) {
          warn "$report->{id} has '==' in '$version' ($and), should be '='.";
          push @sanitized_ands, substr($and, 1);
          next;
        }
        else {
          die "fatal: affected_versions must only begin with '>', '<', '<=', '>=', or '='. Found '$and' in '$version'";
        }
      }
    }
    die "$report->{id} has no acceptable version in $version." if @sanitized_ands == 0;
    if (@sanitized_ands > 1) {
        if (any { $_ =~ /\A=/ } @sanitized_ands) {
          die "$report->{id} has '=' bundled with other clauses in '$version'";
        }
        else {
          my ($gt_count, $lt_count, $lower_end, $higher_end) = (0, 0, undef, undef);
          foreach my $and (@sanitized_ands) {
            if ($and =~ /\A\s*>=?\s*(\d+)/) {
              $lower_end = $1;
              $gt_count++;
            }
            elsif ($and =~ /\A\s*<=?\s*(\d+)/) {
              $higher_end = $1;
              $lt_count++;
            }
          }
          if ($gt_count > 1 || $lt_count > 1) {
            warn "$report->{id} has more than 1 range bundled together in '$version'\n";
          }
          elsif ($gt_count == 1 && $lt_count == 1 && $lower_end > $higher_end) {
            warn "$report->{id} has invalid range in '$version'\n";
          }
        }
      }
      push @sanitized_versions, join(',', @sanitized_ands);
  }
  $report->{affected_versions} = \@sanitized_versions;
  return 1;
}