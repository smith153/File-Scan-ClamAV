use strict;
use Test;
BEGIN { plan tests => 8 }
use File::Scan::ClamAV;
use Cwd;

do "t/mkconf.pl";

# start clamd
my $pid = fork;
die "Fork failed" unless defined $pid;
if (!$pid) {
    exec "$ENV{CLAMD_PATH}/clamd -c clamav.conf";
    die "clamd failed to start: $!";
}
for (1..10) {
  last if (-e "clamsock");
  if (kill(0 => $pid) == 0) {
    die "clamd appears to have died";
  }
  sleep(1);
}

my $av = new File::Scan::ClamAV(port => "clamsock");
ok($av);

my $dir = cwd;
ok($dir);
my $test = "$dir/testfiles/clamavtest";
ok(-f $test);

my $data;
if(open(my $fh, $test)){
	local $/;
	$data = <$fh>;
	close($fh);
}

ok($data);

my ($ans, $vir) = $av->streamscan($data);

ok($ans, 'FOUND');
ok($vir, 'ClamAV-Test-Signature');

ok(kill(9 => $pid), 1);


ok(1, 1);

waitpid($pid, 0);
unlink("clamsock");

