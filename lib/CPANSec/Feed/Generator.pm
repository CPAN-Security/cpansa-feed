package CPANSec::Feed::Generator;

use 5.36.0;
use warnings;
use version;

use Exporter qw(import);
use HTTP::Tiny;
use JSON::MaybeXS qw(decode_json encode_json);
use JSON::Schema::Modern;
use List::Util qw(any all);
use Mojo::Util qw(xml_escape);
use Path::Tiny;
use Time::Piece;

use CPANSec::Feed::FileUtil qw(write_if_changed);
use CPANSec::Feed::VersionRange qw(releases_in_range split_version_range);

our @EXPORT_OK = qw(generate_feed write_feed_json load_metacpan_cache_file metacpan_cache_is_stale html_generation_metadata);

my %METACPAN_RELEASES_BY_DIST;
my %CPANSEC_SKIP_NOTES;
my $LAST_VERSION_RESOLUTION_ERROR;
my $LAST_CVE_LOOKUP_ERROR;
my %WARNING_SUMMARY;
my $METACPAN_CACHE_DIR;
my $METACPAN_CACHE_TTL = 6 * 60 * 60;

sub generate_feed (%args) {
  my $cpansa_db = $args{cpansa_db} // die 'missing cpansa_db';
  my $cve_dir = path($args{cve_dir} // die 'missing cve_dir');
  my $cve_path = $cve_dir->basename eq 'cves' ? $cve_dir : $cve_dir->child('cves');
  die "unable to find base cve dir at $cve_path" if !$cve_path->is_dir;

  %METACPAN_RELEASES_BY_DIST = ();
  %CPANSEC_SKIP_NOTES = ();
  %WARNING_SUMMARY = ();
  $LAST_VERSION_RESOLUTION_ERROR = undef;
  $LAST_CVE_LOOKUP_ERROR = undef;
  $METACPAN_CACHE_DIR = defined $args{metacpan_cache_dir} ? path($args{metacpan_cache_dir}) : undef;
  $METACPAN_CACHE_TTL = $args{metacpan_cache_ttl} // 6 * 60 * 60;

  my ($feed, $report_rows) = _build_feed($cpansa_db, $cve_path);

  _emit_warning_summary();
  _write_html_report($args{report_html}, $report_rows, $args{report_metadata}) if $args{report_html};
  _validate_feed($feed, $args{schema_path}) if $args{schema_path};

  return wantarray ? ($feed, $report_rows) : $feed;
}

sub write_feed_json (%args) {
  my $output = delete $args{output};
  my $output_mode = delete $args{output_mode};
  my $feed = generate_feed(%args);
  my $json = JSON::MaybeXS->new(canonical => 1, utf8 => 1);
  my $encoded = $json->encode($feed);

  if ($output) {
    write_if_changed($output, $encoded, raw => 1, defined $output_mode ? (mode => $output_mode) : ());
  }

  return $encoded;
}

sub _validate_feed ($feed, $schema_path) {
  my $json = JSON::MaybeXS->new(canonical => 1);
  my $js = JSON::Schema::Modern->new(validate_formats => 1);
  my $schema = $json->decode(path($schema_path)->slurp_raw);
  my $schema_id = $schema->{'$id'};
  $js->add_schema($schema);

  my $result = $js->evaluate($schema_id, $feed);
  return if $result->valid;

  die $json->encode($result) . "\n[^] output does not conform to schema";
}

sub _build_feed ($db, $cve_path) {
  my ($cpansa_by_cve, $cpansa_by_dist) = _index_cpansa($db);
  my (%feed, %used_cpansa_ids, %covered_cpansec_cves);
  my @report_rows;

  foreach my $cve (_load_cpansec_cves($cve_path)) {
    my $cve_id = $cve->{cveMetadata}{cveId};
    my $cna = $cve->{containers}{cna} // {};
    my @affected = ref($cna->{affected}) eq 'ARRAY' ? $cna->{affected}->@* : ();

    if (!@affected) {
      push @report_rows, {
        status => 'skipped',
        determination => 'cpansec missing affected data',
        source => 'cvelistV5',
        cna => _cna_short_name($cve),
        distribution => '',
        cve_id => $cve_id,
        cpansa_id => '',
        enriched_fields => '',
        published => _published_from_cve($cve) // '',
        updated => _updated_from_cve($cve) // '',
        title => _fetch_title($cve) // '',
        note => 'CVE has no affected packages',
      };
      next;
    }

    foreach my $affected (@affected) {
      my $dist = _distribution_from_affected($affected);
      if (!$dist) {
        push @report_rows, {
          status => 'skipped',
          determination => 'cpansec missing package name',
          source => 'cvelistV5',
          cna => _cna_short_name($cve),
          distribution => '',
          cve_id => $cve_id,
          cpansa_id => '',
          enriched_fields => '',
          published => _published_from_cve($cve) // '',
        updated => _updated_from_cve($cve) // '',
          title => _fetch_title($cve) // '',
          note => 'Affected entry has no packageName/product',
        };
        next;
      }

      my $cpansa_match = _find_cpansa_match($cpansa_by_cve->{$cve_id}, $dist);
      my $cpansa_enrichment;

      if ($cpansa_match && _apply_hotfixes($cpansa_match, $cpansa_match->{distribution})) {
        $cpansa_enrichment = $cpansa_match;
      }

      my $affected_versions = _affected_versions_from_cve($dist, $affected);
      if (!$affected_versions || !$affected_versions->@*) {
        my $note = 'No usable affected versions in CVE';
        $CPANSEC_SKIP_NOTES{$cve_id}{$dist} = $note;
        push @report_rows, {
          status => 'skipped',
          determination => 'cpansec missing usable versions',
          source => 'cvelistV5',
          cna => _cna_short_name($cve),
          distribution => $dist,
          cve_id => $cve_id,
          cpansa_id => $cpansa_match ? $cpansa_match->{id} : '',
          enriched_fields => '',
          published => _published_from_cve($cve) // '',
        updated => _updated_from_cve($cve) // '',
          title => _fetch_title($cve) // '',
          note => $note,
        };
        next;
      }

      my $affected_releases = _safe_get_versions_from_range($dist, $affected_versions);
      if (!defined $affected_releases) {
        my $note = 'Failed to resolve version range against MetaCPAN releases';
        $note .= ": $LAST_VERSION_RESOLUTION_ERROR" if defined $LAST_VERSION_RESOLUTION_ERROR;
        $CPANSEC_SKIP_NOTES{$cve_id}{$dist} = $note;
        push @report_rows, {
          status => 'skipped',
          determination => 'unresolvable affected releases',
          source => 'cvelistV5',
          cna => _cna_short_name($cve),
          distribution => $dist,
          cve_id => $cve_id,
          cpansa_id => $cpansa_match ? $cpansa_match->{id} : '',
          enriched_fields => '',
          published => _published_from_cve($cve) // '',
        updated => _updated_from_cve($cve) // '',
          title => _fetch_title($cve) // '',
          note => $note,
        };
        next;
      }

      my $record = _compact_record({
        cpansa_id => $cpansa_enrichment ? $cpansa_enrichment->{id} : undef,
        affected_versions => $affected_versions,
        cves => [$cve_id],
        description => _cve_description($cve),
        reported => _reported_from_cve($cve),
        severity => _severity_from_cve($cve),
        distribution => $dist,
        version_range => $affected_versions,
        affected_releases => $affected_releases,
        cve_id => $cve_id,
        cve => $cve,
        title => _fetch_title($cve) // _cve_description($cve),
        references => _cve_references($cve),
      });

      push $feed{$dist}->@*, $record;
      $covered_cpansec_cves{$cve_id} = 1;
      $used_cpansa_ids{$cpansa_enrichment->{id}} = 1 if $cpansa_enrichment;

      push @report_rows, {
        status => 'included',
        determination => 'cpansec authoritative',
        source => 'cvelistV5',
        cna => _cna_short_name($cve),
        distribution => $dist,
        cve_id => $cve_id,
        cpansa_id => $cpansa_enrichment ? $cpansa_enrichment->{id} : '',
        enriched_fields => '',
        published => _published_from_cve($cve) // '',
        updated => _updated_from_cve($cve) // '',
        title => $record->{title} // '',
        note => '',
      };
    }
  }

  foreach my $dist (sort keys $cpansa_by_dist->%*) {
    foreach my $report ($cpansa_by_dist->{$dist}->@*) {
      if ($report->{darkpan} && $report->{darkpan} eq 'true') {
        push @report_rows, {
          status => 'skipped',
          determination => 'darkpan advisory',
          source => 'CPANSA',
          cna => '',
          distribution => $dist,
          cve_id => '',
          cpansa_id => $report->{id} // '',
          enriched_fields => '',
          published => $report->{reported} // '',
        updated => '',
          title => '',
          note => 'DarkPAN advisories are excluded',
        };
        next;
      }

      if ($used_cpansa_ids{$report->{id}}) {
        push @report_rows, {
          status => 'skipped',
          determination => 'covered by cpansec authoritative record',
          source => 'CPANSA',
          cna => '',
          distribution => $dist,
          cve_id => '',
          cpansa_id => $report->{id} // '',
          enriched_fields => '',
          published => $report->{reported} // '',
        updated => '',
          title => '',
          note => 'CVE already covered by CPANSec authoritative record',
        };
        next;
      }

      delete $report->{_skip_reason};
      if (!_apply_hotfixes($report, $dist)) {
        push @report_rows, {
          status => 'skipped',
          determination => 'invalid cpansa advisory',
          source => 'CPANSA',
          cna => '',
          distribution => $dist,
          cve_id => '',
          cpansa_id => $report->{id} // '',
          enriched_fields => '',
          published => $report->{reported} // '',
        updated => '',
          title => '',
          note => $report->{_skip_reason} // 'Sanitization failed',
        };
        next;
      }

      my $cve = _find_cve($cve_path, $report->{cve_id});
      my $is_cpansec = _is_cpansec_cve($cve);
      if (defined $report->{cve_id} && !defined $cve) {
        my $note = $LAST_CVE_LOOKUP_ERROR // 'Referenced CVE could not be resolved from cvelistV5';
        push @report_rows, {
          status => 'skipped',
          determination => 'unresolvable cve payload',
          source => 'CPANSA',
          cna => '',
          distribution => $dist,
          cve_id => $report->{cve_id} // '',
          cpansa_id => $report->{id} // '',
          enriched_fields => '',
          published => $report->{reported} // '',
        updated => '',
          title => '',
          note => $note,
        };
        $CPANSEC_SKIP_NOTES{$report->{cve_id}}{$dist} = $note if $report->{cve_id};
        warn "$report->{id} unable to resolve CVE payload for '$report->{cve_id}'. Skipping.";
        next;
      }

      if ($is_cpansec && $covered_cpansec_cves{$report->{cve_id}}) {
        push @report_rows, {
          status => 'skipped',
          determination => 'covered by cpansec authoritative record',
          source => 'CPANSA',
          cna => _cna_short_name($cve),
          distribution => $dist,
          cve_id => $report->{cve_id} // '',
          cpansa_id => $report->{id} // '',
          enriched_fields => '',
          published => $report->{reported} // '',
        updated => '',
          title => '',
          note => 'Duplicate advisory for a CVE already emitted from cvelistV5',
        };
        next;
      }

      my $affected_releases = _safe_get_versions_from_range($dist, $report->{affected_versions});
      if (!defined $affected_releases) {
        push @report_rows, {
          status => 'skipped',
          determination => 'unresolvable affected releases',
          source => 'CPANSA',
          cna => _cna_short_name($cve),
          distribution => $dist,
          cve_id => $report->{cve_id} // '',
          cpansa_id => $report->{id} // '',
          enriched_fields => '',
          published => $report->{reported} // '',
        updated => '',
          title => '',
          note => $LAST_VERSION_RESOLUTION_ERROR // 'Failed to resolve version range against MetaCPAN releases',
        };
        next;
      }

      my $record = _compact_record({
        cpansa_id => $report->{id},
        affected_versions => $report->{affected_versions},
        cves => $report->{cves},
        description => $report->{description},
        reported => $report->{reported},
        severity => $report->{severity},
        distribution => $dist,
        version_range => $report->{affected_versions},
        affected_releases => $affected_releases,
        cve_id => $report->{cve_id},
        cve => $cve,
        title => _fetch_title($cve) // $report->{description},
        references => $report->{references},
      });

      push $feed{$dist}->@*, $record;
      push @report_rows, {
        status => 'included',
        determination => $is_cpansec ? 'cpansa fallback for cpansec cve'
          : defined $report->{cve_id} ? 'cpansa external cna'
          : 'cpansa only',
        source => 'CPANSA',
        cna => _cna_short_name($cve),
        distribution => $dist,
        cve_id => $report->{cve_id} // '',
        cpansa_id => $report->{id} // '',
        enriched_fields => '',
        published => ($cve ? _published_from_cve($cve) : undef) // $report->{reported} // '',
        updated => ($cve ? _updated_from_cve($cve) : undef) // '',
        title => $record->{title} // '',
        note => $is_cpansec
          ? 'CPANSec CVE was not emitted from cvelistV5; fallback reason: '
            . ($CPANSEC_SKIP_NOTES{$report->{cve_id}}{$dist}
              // $CPANSEC_SKIP_NOTES{$report->{cve_id}}{''}
              // 'unknown')
          : 'Historical advisory sourced from CPANSA',
      };
    }
  }

  return (\%feed, \@report_rows);
}

sub _index_cpansa ($db) {
  my (%by_cve, %by_dist);

  foreach my $dist (sort keys $db->{dists}->%*) {
    my %seen_id;
    my @advisories = grep { !$seen_id{$_->{id} // ''}++ } $db->{dists}{$dist}{advisories}->@*;
    $by_dist{$dist} = \@advisories;

    foreach my $report (@advisories) {
      foreach my $cve_id (_normalize_list($report->{cves})->@*) {
        push $by_cve{$cve_id}->@*, $report;
      }
    }
  }

  return (\%by_cve, \%by_dist);
}

sub _load_cpansec_cves ($cve_path) {
  my @records;

  $cve_path->visit(
    sub ($path, $state) {
      return if !$path->is_file;
      return if $path !~ /\.json\z/;

      my $cve = eval { decode_json($path->slurp_raw) };
      if ($@) {
        warn "unable to parse $path: $@";
        return;
      }
      return if !_is_cpansec_cve($cve);

      push @records, $cve;
    },
    { recurse => 1 },
  );

  return sort {
    ($a->{cveMetadata}{cveId} // '') cmp ($b->{cveMetadata}{cveId} // '')
  } @records;
}

sub _is_cpansec_cve ($cve) {
  return 0 if !$cve || ref($cve) ne 'HASH';
  return 1 if ($cve->{cveMetadata}{assignerShortName} // '') eq 'CPANSec';
  return 1 if ($cve->{containers}{cna}{providerMetadata}{shortName} // '') eq 'CPANSec';
  return 0;
}

sub _distribution_from_affected ($affected) {
  return if !$affected || ref($affected) ne 'HASH';
  return $affected->{packageName} if defined $affected->{packageName} && $affected->{packageName} ne '';
  return $affected->{product} if defined $affected->{product} && $affected->{product} ne '';
  return;
}

sub _affected_versions_from_cve ($dist, $affected) {
  return [] if !$affected || ref($affected) ne 'HASH';
  return [] if ref($affected->{versions}) ne 'ARRAY';

  my @ranges;
  foreach my $version_spec ($affected->{versions}->@*) {
    next if ref($version_spec) ne 'HASH';
    next if defined $version_spec->{status} && $version_spec->{status} ne 'affected';

    my @parts;
    my $start = $version_spec->{version};
    my $less_than = _normalize_cve_version_bound($dist, $version_spec->{versionType}, $version_spec->{lessThan});
    my $less_than_or_equal = _normalize_cve_version_bound($dist, $version_spec->{versionType}, $version_spec->{lessThanOrEqual});
    my $changes_at = _normalize_cve_version_bound($dist, $version_spec->{versionType}, $version_spec->{changesAt});
    if (defined $version_spec->{lessThan}) {
      push @parts, ">=$start" if defined $start && $start ne '' && $start ne '0';
      push @parts, "<$less_than" if !_is_open_ended_bound($less_than);
    }
    elsif (defined $version_spec->{lessThanOrEqual}) {
      push @parts, ">=$start" if defined $start && $start ne '' && $start ne '0';
      push @parts, "<=$less_than_or_equal" if !_is_open_ended_bound($less_than_or_equal);
    }
    elsif (defined $version_spec->{changesAt}) {
      push @parts, ">=$start" if defined $start && $start ne '' && $start ne '0';
      push @parts, "<$changes_at";
    }
    elsif (defined $start && $start ne '') {
      push @parts, "=$start";
    }

    push @ranges, join(',', @parts) if @parts;
  }

  return \@ranges;
}

sub _is_open_ended_bound ($value) {
  return 0 if !defined $value;
  return $value eq '*';
}

sub _normalize_cve_version_bound ($dist, $version_type, $value) {
  return $value if !defined $value || $value eq '';

  if (($dist // '') eq 'perl' && ($version_type // '') eq 'custom' && $value =~ /\A(\d+(?:\.\d+)*)-RC\d+\z/) {
    return $1;
  }

  return $value;
}

sub _find_cpansa_match ($reports, $dist) {
  return if ref($reports) ne 'ARRAY' || !$reports->@*;
  my ($exact) = grep { ($_->{distribution} // '') eq $dist } $reports->@*;
  return $exact // $reports->[0];
}

sub _reported_from_cve ($cve) {
  return _date_only($cve->{cveMetadata}{datePublished})
    // _date_only($cve->{cveMetadata}{dateReserved})
    // _date_only($cve->{cveMetadata}{dateUpdated});
}

sub _published_from_cve ($cve) {
  return _date_only($cve->{cveMetadata}{datePublished});
}

sub _updated_from_cve ($cve) {
  return _date_only($cve->{cveMetadata}{dateUpdated});
}

sub _cna_short_name ($cve) {
  return '' if !$cve || ref($cve) ne 'HASH';
  return $cve->{cveMetadata}{assignerShortName}
    // $cve->{containers}{cna}{providerMetadata}{shortName}
    // '';
}

sub _cve_description ($cve) {
  my $descriptions = $cve->{containers}{cna}{descriptions};
  return if ref($descriptions) ne 'ARRAY';

  foreach my $description ($descriptions->@*) {
    next if ref($description) ne 'HASH';
    return $description->{value} if ($description->{lang} // '') eq 'en' && defined $description->{value};
  }

  foreach my $description ($descriptions->@*) {
    next if ref($description) ne 'HASH';
    return $description->{value} if defined $description->{value};
  }

  return;
}

sub _severity_from_cve ($cve) {
  my $adp = $cve->{containers}{adp};
  return if ref($adp) ne 'ARRAY';

  foreach my $container ($adp->@*) {
    next if ref($container) ne 'HASH';
    next if ref($container->{metrics}) ne 'ARRAY';
    foreach my $metric ($container->{metrics}->@*) {
      next if ref($metric) ne 'HASH';
      my $severity = lc($metric->{cvssV3_1}{baseSeverity} // '');
      return $severity if $severity =~ /\A(?:minor|medium|moderate|high|critical)\z/;
    }
  }

  return;
}

sub _cve_references ($cve) {
  my $references = $cve->{containers}{cna}{references};
  return [] if ref($references) ne 'ARRAY';

  my @urls;
  foreach my $reference ($references->@*) {
    next if ref($reference) ne 'HASH';
    push @urls, $reference->{url} if defined $reference->{url} && $reference->{url} ne '';
  }

  return _merge_lists(\@urls, []);
}

sub _compact_record ($record) {
  my %copy = $record->%*;
  foreach my $key (keys %copy) {
    delete $copy{$key} if !defined $copy{$key};
  }
  return \%copy;
}

sub _normalize_list ($value) {
  return [] if !defined $value || $value eq '';
  return [ grep { defined && $_ ne '' } $value->@* ] if ref($value) eq 'ARRAY';
  return [$value];
}

sub _merge_lists ($left, $right) {
  my %seen;
  my @merged;

  foreach my $value (_normalize_list($left)->@*, _normalize_list($right)->@*) {
    next if $seen{$value}++;
    push @merged, $value;
  }

  return \@merged;
}

sub _date_only ($value) {
  return if !defined $value || $value eq '';
  return $1 if $value =~ /\A(\d{4}-\d{2}-\d{2})/;
  return;
}

sub _fetch_title ($cve) {
  return unless $cve && ref $cve;
  return $cve->{containers}{cna}{title};
}

sub _find_cve ($cve_path, $cve_id) {
  $LAST_CVE_LOOKUP_ERROR = undef;
  return unless $cve_id;
  if ($cve_id !~ /\ACVE-(\d{4})-(\d+)\z/) {
    $LAST_CVE_LOOKUP_ERROR = "non-CVE identifier '$cve_id'";
    warn $LAST_CVE_LOOKUP_ERROR;
    return;
  }

  my ($year, $n) = ($1, $2);
  my $n_len = length($n);
  my $complete_path;
  while ($n_len > 0) {
    my $dir = substr($n, 0, $n_len) . ('x' x (length($n) - $n_len));
    $n_len--;
    $complete_path = $cve_path->child($year, $dir, $cve_id . '.json');
    last if $complete_path->is_file;
    $complete_path = undef;
  }

  unless ($complete_path) {
    $LAST_CVE_LOOKUP_ERROR = "unable to find $cve_id in cvelistV5";
    warn $LAST_CVE_LOOKUP_ERROR;
    return;
  }

  return decode_json($complete_path->slurp_raw);
}

sub _safe_get_versions_from_range ($distname, $version_range) {
  $LAST_VERSION_RESOLUTION_ERROR = undef;
  my $result = eval { _get_versions_from_range($distname, $version_range) };
  if ($@) {
    chomp(my $error = $@);
    $LAST_VERSION_RESOLUTION_ERROR = $error;
    warn "unable to resolve affected releases for $distname: $error\n";
    return;
  }
  return $result;
}

sub _get_versions_from_range ($distname, $version_range) {
  my $clauses = split_version_range($distname, $version_range);
  my $all_versions = $METACPAN_RELEASES_BY_DIST{$distname};
  if (!$all_versions) {
    $all_versions = _load_metacpan_cache($distname) // _fetch_metacpan_releases($distname);
    $METACPAN_RELEASES_BY_DIST{$distname} = $all_versions;
  }

  return releases_in_range($all_versions, $clauses);
}

sub _fetch_metacpan_releases ($distname) {
  my $response = HTTP::Tiny->new->post('https://fastapi.metacpan.org/release?size=5000', {
    content => encode_json({
      query  => { term => { distribution => $distname } },
      fields => ['version', 'version_numified', 'author'],
    }),
    headers => {
      'content-type' => 'application/json',
      accept => 'application/json',
    },
  });

  die "MetaCPAN request failed for $distname: $response->{status} $response->{reason}" if !$response->{success};

  my $decoded = decode_json($response->{content});
  my @fetched_versions;
  foreach my $entry ($decoded->{hits}{hits}->@*) {
    next if !defined $entry->{fields}{version_numified};
    push @fetched_versions, {
      release => $entry->{fields}{author} . '/' . $distname . '-' . $entry->{fields}{version},
      version => version->parse($entry->{fields}{version_numified}),
      version_numified => $entry->{fields}{version_numified},
    };
  }

  _store_metacpan_cache($distname, \@fetched_versions);
  return \@fetched_versions;
}

sub _load_metacpan_cache ($distname) {
  my $cache_file = _metacpan_cache_file($distname);
  return if !$cache_file || !$cache_file->is_file;
  return load_metacpan_cache_file($cache_file, ttl => $METACPAN_CACHE_TTL);
}

sub _store_metacpan_cache ($distname, $versions) {
  my $cache_file = _metacpan_cache_file($distname);
  return if !$cache_file;

  $cache_file->parent->mkpath;
  my @serializable = map {
    +{
      release => $_->{release},
      version_numified => $_->{version_numified},
    }
  } $versions->@*;

  my $tmp = $cache_file->sibling($cache_file->basename . '.tmp');
  $tmp->spew_raw(encode_json(\@serializable));
  $tmp->move($cache_file);
}

sub _metacpan_cache_file ($distname) {
  return if !$METACPAN_CACHE_DIR;
  my $hex = unpack('H*', $distname);
  return $METACPAN_CACHE_DIR->child($hex . '.json');
}

sub load_metacpan_cache_file ($cache_file, %args) {
  $cache_file = path($cache_file);
  return if !$cache_file->is_file;
  return if metacpan_cache_is_stale($cache_file, $args{ttl});

  my $decoded = eval { decode_json($cache_file->slurp_raw) };
  if ($@ || ref($decoded) ne 'ARRAY') {
    warn "ignoring invalid MetaCPAN cache $cache_file";
    return;
  }

  my @versions;
  foreach my $entry ($decoded->@*) {
    next if ref($entry) ne 'HASH';
    next if !defined $entry->{release} || !defined $entry->{version_numified};
    push @versions, {
      release => $entry->{release},
      version => version->parse($entry->{version_numified}),
      version_numified => $entry->{version_numified},
    };
  }

  return \@versions;
}

sub metacpan_cache_is_stale ($cache_file, $ttl = undef) {
  $ttl //= $METACPAN_CACHE_TTL;
  return 0 if !defined $ttl || $ttl <= 0;

  my $stat = $cache_file->stat;
  return 1 if !$stat;

  my $age = time - $stat->mtime;
  return $age > $ttl;
}

sub _skip_report ($report, $reason) {
  my $id = $report->{id} // '<unknown>';
  $report->{_skip_reason} = $reason;
  warn "$id $reason. Skipping.";
  return;
}

sub _record_warning_stat ($category, $report_id, $count = 1, @examples) {
  my $bucket = ($WARNING_SUMMARY{$category} //= {
    reports => 0,
    clauses => 0,
    seen_report => {},
    examples => [],
  });

  if (!$bucket->{seen_report}{$report_id}++) {
    $bucket->{reports}++;
  }
  $bucket->{clauses} += $count;

  foreach my $example (@examples) {
    next if !defined $example || $example eq '';
    next if grep { $_ eq $example } $bucket->{examples}->@*;
    push $bucket->{examples}->@*, $example;
    last if $bucket->{examples}->@* >= 5;
  }
}

sub _emit_warning_summary () {
  my %labels = (
    multi_cve => 'CPANSA advisories reference more than one CVE',
    leading_space => 'CPANSA affected_versions had leading whitespace',
    missing_sign => "CPANSA affected_versions omitted an operator and were normalized to '='",
    double_equals => "CPANSA affected_versions used '==' and were normalized to '='",
  );

  foreach my $category (sort keys %WARNING_SUMMARY) {
    my $bucket = $WARNING_SUMMARY{$category};
    my $message = $labels{$category} // $category;
    my $line = sprintf(
      "%s: %d advisories, %d clauses",
      $message,
      $bucket->{reports},
      $bucket->{clauses},
    );
    if ($bucket->{examples}->@*) {
      $line .= ' (examples: ' . join(', ', $bucket->{examples}->@*) . ')';
    }
    warn "$line\n";
  }
}

sub _apply_hotfixes ($report, $dist) {
  return _skip_report($report, 'missing affected_versions') if !defined $report->{affected_versions};
  return _skip_report($report, 'missing distribution') if !defined $report->{distribution};

  if ($report->{distribution} ne $dist) {
    return _skip_report($report, "has mixed dists: $report->{distribution} and $dist");
  }

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

  if (!all { defined } $report->{affected_versions}->@*) {
    return _skip_report($report, 'has undefined values in affected_versions');
  }

  if ($report->{cves}->@* > 1) {
    _record_warning_stat('multi_cve', $report->{id}, 1, $report->{id});
  }
  $report->{cve_id} = $report->{cves}[0];

  my @sanitized_versions;
  my (@missing_sign_examples, @double_equals_examples, @leading_space_examples);
  my ($missing_sign_count, $double_equals_count, $leading_space_count) = (0, 0, 0);
  foreach my $version ($report->{affected_versions}->@*) {
    my @raw_ands = split /,/ => $version;
    my @sanitized_ands;

    foreach my $and (@raw_ands) {
      if ($and =~ /\A\s+/) {
        $leading_space_count++;
        push @leading_space_examples, $and if @leading_space_examples < 3;
        $and =~ s/\A\s+//;
      }

      if ($and =~ /\A(>=?|<=?|=)\d/) {
        push @sanitized_ands, $and;
      }
      else {
        if ($and =~ /\A\d/) {
          $missing_sign_count++;
          push @missing_sign_examples, $and if @missing_sign_examples < 3;
          push @sanitized_ands, "=$and";
          next;
        }
        elsif ($and =~ /\A==\d/) {
          $double_equals_count++;
          push @double_equals_examples, $and if @double_equals_examples < 3;
          push @sanitized_ands, substr($and, 1);
          next;
        }
        else {
          return _skip_report(
            $report,
            "has unparseable affected_versions clause '$and' in '$version'",
          );
        }
      }
    }

    return _skip_report($report, "has no acceptable version in '$version'") if @sanitized_ands == 0;

    if (@sanitized_ands > 1) {
      if (any { $_ =~ /\A=/ } @sanitized_ands) {
        return _skip_report(
          $report,
          "has ambiguous affected_versions '$version' ('=' bundled with range clauses)",
        );
      }

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
      warn "$report->{id} has more than 1 range bundled together in '$version'\n" if $gt_count > 1 || $lt_count > 1;
      warn "$report->{id} has invalid range in '$version'\n" if $gt_count == 1 && $lt_count == 1 && $lower_end > $higher_end;
    }

    push @sanitized_versions, join(',', @sanitized_ands);
  }

  _record_warning_stat('leading_space', $report->{id}, $leading_space_count, @leading_space_examples)
    if $leading_space_count;
  _record_warning_stat('missing_sign', $report->{id}, $missing_sign_count, @missing_sign_examples)
    if $missing_sign_count;
  _record_warning_stat('double_equals', $report->{id}, $double_equals_count, @double_equals_examples)
    if $double_equals_count;

  $report->{affected_versions} = \@sanitized_versions;
  delete $report->{_skip_reason};
  return 1;
}

sub _metadata_list_html ($metadata) {
  return '<li><strong>Unavailable</strong></li>' if ref($metadata) ne 'HASH' || !keys $metadata->%*;

  return join "\n", map {
    my $value = defined $metadata->{$_} && $metadata->{$_} ne '' ? $metadata->{$_} : 'n/a';
    '<li><strong>' . xml_escape($_) . '</strong>: ' . xml_escape($value) . '</li>'
  } sort keys $metadata->%*;
}

sub _write_html_report ($path, $rows, $metadata = undef) {
  my $out = path($path);
  $out->parent->mkpath;

  my $metadata_html = _metadata_list_html($metadata);

  # Deduplicate: one row per vulnerability.
  # Prefer 'included' over 'skipped' when both exist for the same advisory.
  my (%seen_key, %included_cpansa);
  my @deduped;
  # Process included first so they win over skipped duplicates
  my @ordered = sort {
    (($a->{status} // '') eq 'included' ? 0 : 1) <=> (($b->{status} // '') eq 'included' ? 0 : 1)
  } $rows->@*;
  for my $row (@ordered) {
    my $dist = $row->{distribution} // '';
    my $cve = $row->{cve_id} // '';
    my $cpansa = $row->{cpansa_id} // '';
    my $key = join("\0", $cve, $cpansa, $dist);
    next if $seen_key{$key}++;
    # If this CPANSA ID was already included (via a CVE row), skip regardless of distribution
    if ($cpansa ne '' && $cve eq '' && $included_cpansa{$cpansa}) {
      next;
    }
    $included_cpansa{$cpansa} = 1 if $cpansa ne '' && ($row->{status} // '') eq 'included';
    push @deduped, $row;
  }

  my @sorted = sort { ($b->{published} // '') cmp ($a->{published} // '') } @deduped;

  my %status_counts;
  foreach my $row (@sorted) {
    $status_counts{_display_status($row)}++;
  }

  my @status_order = grep { $status_counts{$_} } (
    'CPANSec CVE', 'CPANSA (external CNA)', 'CPANSA only', 'CPANSA (CPANSec fallback)',
    sort grep { !/^CPANSec CVE$|^CPANSA / } keys %status_counts
  );
  my $summary_html = join "\n", map {
    '<li><strong>' . xml_escape($_) . '</strong>: ' . ($status_counts{$_} // 0) . '</li>'
  } @status_order;

  my $rows_html = join "\n", map { _report_table_row($_) } @sorted;

  write_if_changed($out, <<"HTML", mode => 0644);
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>CPANSec Feed validation report</title>
  <style>
    :root { color-scheme: light; }
    body { font-family: system-ui, -apple-system, sans-serif; margin: 2rem; background: #f6f3ea; color: #1d1a16; font-size: 0.9rem; }
    h1, h2 { margin-bottom: 0.3rem; }
    p { max-width: 70rem; }
    .meta { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1rem; margin: 1.5rem 0; align-items: start; }
    .card { background: #fffdf8; border: 1px solid #d9cdb8; padding: 1rem 1.2rem; }
    .card ul { margin: 0.5rem 0 0; padding-left: 1.25rem; }
    .card li { overflow-wrap: anywhere; }
    table { width: 100%; border-collapse: collapse; background: #fffdf8; }
    th, td { border: 1px solid #d9cdb8; padding: 0.35rem 0.5rem; text-align: left; vertical-align: top; }
    th { background: #efe4cf; position: sticky; top: 0; z-index: 1; }
    th.sortable { cursor: pointer; user-select: none; }
    th.sortable:hover { background: #e5d9c0; }
    th.sortable::after { content: ' \\2195'; color: #8b7355; font-size: 0.8em; }
    th.sort-asc::after { content: ' \\2191'; color: #1d1a16; }
    th.sort-desc::after { content: ' \\2193'; color: #1d1a16; }
    tbody tr:nth-child(odd) { background: #fcf8ef; }
    tr.skip { background: #fdf0f0 !important; }
    .table-wrap { overflow-x: auto; }
    td.id { font-family: ui-monospace, monospace; font-size: 0.85em; white-space: nowrap; }
    td.date { white-space: nowrap; font-size: 0.85em; }
    .rel { color: #8b7355; font-size: 0.85em; }
    a { color: #4a6fa5; text-decoration: none; }
    a:hover { text-decoration: underline; }
    td.title { max-width: 20rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    \@media (max-width: 1200px) { td.title { max-width: 12rem; } }
    \@media (max-width: 1000px) { .meta { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <h1>CPANSec Feed validation report</h1>
  <p>Advisory source decisions, sorted newest first. For manual validation of feed contents.</p>
  <div class="meta">
    <section class="card">
      <h2>Summary</h2>
      <ul>
$summary_html
      </ul>
    </section>
    <section class="card">
      <h2>Source Metadata</h2>
      <ul>
$metadata_html
      </ul>
    </section>
  </div>
  <div class="table-wrap">
    <table id="report">
      <thead>
        <tr>
          <th class="sortable" data-col="0" data-type="text">Published</th>
          <th class="sortable" data-col="1" data-type="text">Updated</th>
          <th>CVE</th>
          <th class="sortable" data-col="3" data-type="text">Distribution</th>
          <th>Title</th>
          <th class="sortable" data-col="5" data-type="text">Status</th>
          <th>CNA</th>
          <th>Note</th>
        </tr>
      </thead>
      <tbody>
$rows_html
      </tbody>
    </table>
  </div>
  <script>
  // Append relative time to <time> elements
  (function() {
    var times = document.querySelectorAll('time[datetime]');
    var now = Date.now();
    times.forEach(function(el) {
      var d = new Date(el.getAttribute('datetime'));
      if (isNaN(d)) return;
      var diff = now - d.getTime();
      var days = Math.floor(diff / 86400000);
      var label;
      if (days < 0) label = 'future';
      else if (days === 0) label = 'today';
      else if (days === 1) label = '1d ago';
      else if (days < 30) label = days + 'd ago';
      else if (days < 365) label = Math.floor(days / 30) + 'mo ago';
      else { var y = Math.floor(days / 365); label = y + 'y ago'; }
      var span = document.createElement('span');
      span.className = 'rel';
      span.textContent = ' (' + label + ')';
      el.parentNode.appendChild(span);
    });
  })();

  // Column sorting
  (function() {
    var table = document.getElementById('report');
    if (!table) return;
    var headers = table.querySelectorAll('th.sortable');
    var tbody = table.querySelector('tbody');
    var currentCol = -1, currentDir = 0;

    headers.forEach(function(th) {
      th.addEventListener('click', function() {
        var col = parseInt(th.getAttribute('data-col'));
        var dir;
        if (currentCol === col) { dir = currentDir === 1 ? -1 : 1; }
        else { dir = 1; }
        currentCol = col; currentDir = dir;

        headers.forEach(function(h) { h.classList.remove('sort-asc', 'sort-desc'); });
        th.classList.add(dir === 1 ? 'sort-asc' : 'sort-desc');

        var rows = Array.from(tbody.querySelectorAll('tr'));
        rows.sort(function(a, b) {
          var at = (a.children[col] || {}).getAttribute && a.children[col].getAttribute('data-sort') || a.children[col].textContent || '';
          var bt = (b.children[col] || {}).getAttribute && b.children[col].getAttribute('data-sort') || b.children[col].textContent || '';
          return dir * at.localeCompare(bt);
        });
        rows.forEach(function(r) { tbody.appendChild(r); });
      });
    });
  })();
  </script>
</body>
</html>
HTML
}

sub _display_status ($row) {
  my $det = $row->{determination} // '';
  return 'CPANSec CVE'                if $det eq 'cpansec authoritative';
  return 'CPANSA (external CNA)'      if $det eq 'cpansa external cna';
  return 'CPANSA only'                if $det eq 'cpansa only';
  return 'CPANSA (CPANSec fallback)'   if $det eq 'cpansa fallback for cpansec cve';
  return 'skipped: ' . $det           if ($row->{status} // '') eq 'skipped';
  return $det || $row->{status} // '';
}

sub _report_table_row ($row) {
  my $status = $row->{status} // '';
  my $row_class = $status eq 'skipped' ? ' class="skip"' : '';

  my $cve_id = $row->{cve_id} // '';

  my $note = $row->{note} // '';
  if ($row->{cpansa_id} && $row->{cpansa_id} ne '') {
    my $cpansa_link = _cpansa_link($row->{cpansa_id}, $row->{distribution});
    $note = $cpansa_link . ($note ne '' ? '; ' . xml_escape($note) : '');
  }
  else {
    $note = xml_escape($note);
  }

  my $title = $row->{title} // '';

  my $cve_html = $cve_id ne ''
    ? '<a href="https://www.cve.org/CVERecord?id=' . xml_escape($cve_id) . '">' . xml_escape($cve_id) . '</a>'
    : '';

  return '<tr' . $row_class . '>'
    . _time_td($row->{published})
    . _time_td($row->{updated})
    . '<td class="id">' . $cve_html . '</td>'
    . '<td>' . xml_escape($row->{distribution} // '') . '</td>'
    . '<td class="title" title="' . xml_escape($title) . '">' . xml_escape($title) . '</td>'
    . '<td>' . xml_escape(_display_status($row)) . '</td>'
    . '<td>' . xml_escape($row->{cna} // '') . '</td>'
    . '<td>' . $note . '</td>'
    . '</tr>';
}

sub _cpansa_link ($cpansa_id, $dist) {
  my $file = 'CPANSA-' . ($dist // '') . '.yml';
  my $url = 'https://github.com/briandfoy/cpan-security-advisory/blob/master/cpansa/' . $file;
  return '<a href="' . xml_escape($url) . '">' . xml_escape($cpansa_id) . '</a>';
}

sub _time_td ($date) {
  return '<td class="date"></td>' if !defined $date || $date eq '';
  my $escaped = xml_escape($date);
  return '<td class="date" data-sort="' . $escaped . '"><time datetime="' . $escaped . '">' . $escaped . '</time></td>';
}

sub html_generation_metadata (%args) {
  my $generated_at = $args{generated_at} // gmtime()->datetime . 'Z';
  my $cpansa = $args{cpansa} // {};
  my $cvelist = $args{cvelist} // {};

  my %metadata = (
    'generated at' => $generated_at,
  );

  if (ref($cpansa) eq 'HASH') {
    $metadata{'cpansa source url'} = $cpansa->{url} if defined $cpansa->{url};
    $metadata{'cpansa source commit'} = $cpansa->{meta}{commit} if ref($cpansa->{meta}) eq 'HASH' && defined $cpansa->{meta}{commit};
    $metadata{'cpansa source date'} = $cpansa->{meta}{date} if ref($cpansa->{meta}) eq 'HASH' && defined $cpansa->{meta}{date};
    $metadata{'cpansa downloaded at'} = $cpansa->{fetched_at} if defined $cpansa->{fetched_at};
    $metadata{'cpansa file time'} = $cpansa->{file_mtime} if defined $cpansa->{file_mtime};
  }

  if (ref($cvelist) eq 'HASH') {
    $metadata{'cvelist repo'} = $cvelist->{repo} if defined $cvelist->{repo};
    $metadata{'cvelist head'} = $cvelist->{head} if defined $cvelist->{head};
    $metadata{'cvelist head time'} = $cvelist->{head_time} if defined $cvelist->{head_time};
    $metadata{'cvelist updated at'} = $cvelist->{fetched_at} if defined $cvelist->{fetched_at};
  }

  return \%metadata;
}

1;
