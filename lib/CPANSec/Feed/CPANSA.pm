package CPANSec::Feed::CPANSA;

use 5.36.0;
use warnings;

use Exporter qw(import);
use HTTP::Tiny;
use JSON::MaybeXS qw(decode_json);
use Path::Tiny;
use Time::Piece;

our @EXPORT_OK = qw(latest_release_url load_database download_database);

sub latest_release_url () {
  return 'https://github.com/briandfoy/cpan-security-advisory/releases/latest/download/cpan-security-advisory.json';
}

sub load_database ($path) {
  my $file = path($path);
  die "CPANSA JSON not found at $file" if !$file->is_file;

  my $db = decode_json($file->slurp_raw);
  die "CPANSA JSON at $file is missing top-level dists" if ref($db) ne 'HASH' || ref($db->{dists}) ne 'HASH';

  return $db;
}

sub download_database ($destination, %args) {
  my $url = $args{url} // latest_release_url();
  my $http = $args{http} // HTTP::Tiny->new(
    agent => 'CPANSec-Feed/0.1',
    default_headers => {
      accept => 'application/json',
    },
  );

  my $response = $http->get($url);
  die "unable to download CPANSA JSON from $url: $response->{status} $response->{reason}"
    if !$response->{success};

  my $decoded = eval { decode_json($response->{content}) };
  die "downloaded CPANSA JSON from $url is invalid: $@" if !$decoded || $@;
  die "downloaded CPANSA JSON from $url is missing top-level dists"
    if ref($decoded) ne 'HASH' || ref($decoded->{dists}) ne 'HASH';

  my $file = path($destination);
  $file->parent->mkpath;
  my $tmp = $file->sibling($file->basename . '.tmp');
  $tmp->spew_raw($response->{content});
  $tmp->move($file);
  my $stat = $file->stat;
  my $mtime = $stat ? $stat->mtime : undef;

  return {
    path => $file->stringify,
    url => $url,
    dists => scalar keys $decoded->{dists}->%*,
    meta => $decoded->{meta},
    fetched_at => gmtime()->datetime . 'Z',
    file_mtime => defined $mtime ? gmtime($mtime)->datetime . 'Z' : undef,
  };
}

1;
