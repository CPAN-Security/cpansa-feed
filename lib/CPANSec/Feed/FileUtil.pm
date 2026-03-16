package CPANSec::Feed::FileUtil;

use 5.36.0;
use warnings;

use Exporter qw(import);
use Path::Tiny;

our @EXPORT_OK = qw(write_if_changed);

sub write_if_changed ($path, $content, %args) {
  my $file = path($path);
  $file->parent->mkpath;

  my $is_raw = $args{raw} // 0;
  if ($file->is_file) {
    my $existing = $is_raw ? $file->slurp_raw : $file->slurp_utf8;
    return 0 if $existing eq $content;
  }

  my $tmp = $file->sibling($file->basename . '.tmp');
  if ($is_raw) {
    $tmp->spew_raw($content);
  }
  else {
    $tmp->spew_utf8($content);
  }
  $tmp->move($file);
  return 1;
}

1;
