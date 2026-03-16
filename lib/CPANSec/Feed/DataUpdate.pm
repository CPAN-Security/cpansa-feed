package CPANSec::Feed::DataUpdate;

use 5.36.0;
use warnings;

use Exporter qw(import);
use Path::Tiny;

use CPANSec::Feed::CPANSA qw(download_database);

our @EXPORT_OK = qw(update_cpansa_json update_cvelist_repo);

sub update_cpansa_json ($destination, %args) {
  return download_database($destination, %args);
}

sub update_cvelist_repo ($destination, %args) {
  my $repo = $args{repo} // 'https://github.com/CVEProject/cvelistV5.git';
  my $dir = path($destination);

  if (!$dir->child('.git')->is_dir) {
    _run([
      'git', 'clone', '--depth', '1', '--single-branch', $repo, $dir->stringify,
    ]);
  }
  else {
    _run(['git', '-C', $dir->stringify, 'pull', '--ff-only']);
  }

  my $head = _capture(['git', '-C', $dir->stringify, 'rev-parse', '--short=12', 'HEAD']);

  return {
    path => $dir->stringify,
    repo => $repo,
    head => $head,
  };
}

sub _run ($argv) {
  system($argv->@*) == 0 or die "command failed: @$argv";
}

sub _capture ($argv) {
  open my $fh, '-|', $argv->@* or die "unable to run @$argv: $!";
  local $/;
  my $out = <$fh>;
  close $fh or die "command failed: @$argv";
  $out =~ s/\s+\z//;
  return $out;
}

1;
