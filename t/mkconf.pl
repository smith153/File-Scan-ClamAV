use Cwd;

die "No CLAMD_PATH environment!" unless $ENV{CLAMD_PATH};

open(CONF, ">clamav.conf") || die "Cannot write: $!";

my $dir = cwd;

print CONF <<"EOCONF";
LocalSocket $dir/clamsock
Foreground true
MaxThreads 1
ScanArchive true
  
EOCONF

close CONF;
