# $Id: ClamAV.pm,v 1.91 2009/02/07 12:43:13 jamtur Exp $
# Author: Colin Faber cfaber@fpsn.net, James Turnbull james@lovedthanlost.net

package File::Scan::ClamAV;
use strict;
use warnings;
use vars qw($VERSION);
use File::Find qw(find);
use IO::Socket;

$VERSION = $1 if('$Id: ClamAV.pm,v 1.91 2009/02/07 12:43:13 jamtur Exp $' =~ /,v ([\d.]+) /);

=head1 NAME

File::Scan::ClamAV - Connect to a local Clam Anti-Virus clamd service and send commands

=head1 SYNOPSIS

 my $av = new File::Scan::ClamAV;
 if($av->ping){
	my %found = $av->scan('/tmp');
	for my $file (keys %found){
		print "Found virus: $found{$file} in $file\n";
	}
 }

=head1 DESCRIPTION

This module provides a simplified perl interface onto a local clam anti-virus scanner, allowing you to do fast virus scans on files on your local hard drive, or streamed data.

=head1 METHODS

=head2 new()

Create a new File::Scan::ClamAV object. By default tries to connect to a local unix domain socket at F</tmp/clamd>. Options are passed in as key/value pairs.

B<Available Options:>

=over 4

=item * port

A port or socket to connect to if you do not wish to use the unix domain socket at F</tmp/clamd>. If the socket has been setup as a TCP/IP socket (see the C<TCPSocket> option in the F<clamav.conf> file), then specifying in a number will cause File::Scan::ClamAV to use a TCP socket.

Examples:

  my $av = new File::Scan::ClamAV; # Default - uses /tmp/clamd socket
  
  # Use the unix domain socket at /var/sock/clam
  my $av = new File::Scan::ClamAV(port => '/var/sock/clam');
  
  # Use tcp/ip at port 3310
  my $av = new File::Scan::ClamAV(port => 3310);

Note: there is no way to connect to a clamd on another machine. The reason for this is that clamd can only scan local files, so there would not be much point in doing this (unless you had NFS shares). Plus if you are using TCP/IP clamd appears to bind to all adaptors, so it is probably insecure. -ms

=item * find_all

By default the ClamAV clamd service will stop scanning at the first virus it detects. This is useful for performance, but sometimes you want to find all possible viruses in all of the files. To do that, specify a true value for find_all.

Examples:

  # Stop at first virus
  use File::Scan::ClamAV;

  my $av = new File::Scan::ClamAV;
  my ($file, $virus) = $av->scan('/home/bob');
  


  # Return all viruses
  use File::Scan::ClamAV;
  my $av = new File::Scan::ClamAV(find_all => 1);
  my %caught = $av->scan('/home/bob');



  # Scan a file from command line:
  perl -MFile::Scan::ClamAV -e 'printf("%s: %s\n", File::Scan::ClamAV->new->scan($ARGV[0]))' /home/bob/file.zip



  # Preform a stream-scan on a scalar
  use File::Scan::ClamAV;

  if($ARGV[0] =~ /(.+)/){
	my $file = $1;

	if(-f $file){
		my $data;
		if(open(my $fh, $file)){
			local $/;
			$data = <$fh>;
			close($fh);
		} else {
			die "Unable to read file: $file $!\n";
		}

		my $av = new File::Scan::ClamAV;

		my ($code, $virus) = $av->streamscan($data);

		if($code eq 'OK'){
			print "The file: $file did not contain any virus known to ClamAV\n";
		} elsif($code eq 'FOUND'){
			print "The file: $file contained the virus: $virus\n";
		} else {
			print $av->errstr . "\n";
		}
	} else {
		print "Unknown file: $file\n";
	}
 }

=back

=cut

sub new {
    my $class = shift;
    my (%options) = @_;
    $options{port} ||= '/tmp/clamd';
    $options{find_all} ||= 0;
    return bless \%options, $class;
}

=head2 ping()

Pings the clamd to check it is alive. Returns true if it is alive, false if it is dead. Note that it is still possible for a race condition to occur between your test for ping() and any call to scan(). See below for more details.

On error nothing is returned and the errstr() error handler is set.

=cut

sub ping {
 my ($self) = @_;
 my $conn = $self->_get_connection || return;

 $self->_send($conn, "PING\n");
 chomp(my $response = $conn->getline);

 # Run out the buffer?
 1 while (<$conn>);

 $conn->close;

 return ($response eq 'PONG' ? 1 : $self->_seterrstr("Unknown reponse from ClamAV service: $response"));
}

=head2 scan($dir_or_file)

Scan a directory or a file. Note that the resource must be readable by the user the ClamdAV clamd service is running as.

Returns a hash of C<< filename => virusname >> mappings.

On error nothing is returned and the errstr() error handler is set. If no virus is found nothing will be returned and the errstr() error handle won't be set.

=cut

sub scan {
 my $self = shift;
 $self->_seterrstr;
 my @results;

 if($self->{find_all}){
	@results = $self->_scan('SCAN', @_);
 } else {
	@results = $self->_scan_shallow('SCAN', @_);
 }

 my %f;
 for(@results){
	$f{ $_->[0] } = $_->[1];
 }

 if(%f){
	return %f;
 } else {
	return;
 }
}

=head2 rawscan($dir_or_file)

This method has been deprecated - use scan() instead

=cut

sub rawscan {
 warn "The rawscan() method is deprecated - using scan() instead";
 shift->scan(@_);
}

=head2 streamscan($data);

Preform a scan on a stream of data for viruses with the ClamAV clamd module.

Returns a list of two arguments: the first being the response which will be 'OK' or 'FOUND' the second being the virus found - if a virus is found.

On failure it sets the errstr() error handler.

=cut

sub streamscan {
 my ($self) = shift;

 my $data = join '', @_;

 $self->_seterrstr;

 my $conn = $self->_get_connection || return;
 $self->_send($conn, "STREAM\n");
 chomp(my $response = $conn->getline);

 my @return;
 if($response =~ /^PORT (\d+)/){
	if((my $c = $self->_get_tcp_connection($1))){
		$self->_send($c, $data);
		$c->close;

		chomp(my $r = $conn->getline);
		if($r =~ /stream: (.+) FOUND/i){
			@return = ('FOUND', $1);
		} else {
			@return = ('OK');
		}
	} else {
		$conn->close;
		return;
	}
 }
 $conn->close;
 return @return;
}

=head2 quit()

Sends the QUIT message to clamd, causing it to cleanly exit.

This may or may not work, I think due to bugs in clamd's C code (it does not waitpid after a child exit, so you get zombies). However it seems to be fine on BSD derived operating systems (i.e. it's just broken under Linux). -ms

The test file t/03quit.t will currently wait 5 seconds before trying a kill -9 to get rid of the process. You may have to do something similar on Linux, or just don't use this method to kill Clamd - use C<kill `cat /path/to/clamd.pid`> instead which seems to work fine. -ms

=cut

sub quit {
 my $self = shift;
 my $conn = $self->_get_connection || return;
 $self->_send($conn, "QUIT\n");
 1 while (<$conn>);
 $conn->close;
 return 1;
}

=head2 reload()

Cause ClamAV clamd service to reload its virus database.

=cut

sub reload {
 my $self = shift;
 my $conn = $self->_get_connection || return;
 $self->_send($conn, "RELOAD\n");

 my $response = $conn->getline;
 1 while (<$conn>);
 $conn->close;
 return 1;
}

=head2 errstr()

Return the last error message.

=cut

sub errstr {
 my ($self, $err) = @_;
 $self->{'.errstr'} = $err if $err;
 return $self->{'.errstr'};
}

sub _scan {
 my $self = shift;
 my $cmd = shift;
 my $options = {};

 if(ref($_[-1]) eq 'HASH') {
	$options = pop(@_);
 }
    
 # Ugh - a bug in clamd makes us do every file
 # on a separate connection! So we will do a File::Find
 # ourselves to get all the files, then do each on
 # a separate connection to the daemon. Hopefully
 # this bug will be fixed and I can remove this horrible
 # hack. -ms
    
 # Files
 my @files = grep { -f $_ } @_;
    
 # Directories
 for my $dir (@_){
	next unless -d $dir;
	find(sub {
		if(-f $File::Find::name) {
			push @files, $File::Find::name;
		}
	}, $dir);
 }

 if(!@files) {
	return $self->_seterrstr("scan() requires that you specify a directory or file to scan");
 }
    
 my @results;

 for(@files){
	push @results, $self->_scan_shallow($cmd, $_, $options);
 }

 return @results;
}

sub _scan_shallow {
 # same as _scan, but stops at first virus
 my $self = shift;
 my $cmd = shift;
 my $options = {};

 if(ref($_[-1]) eq 'HASH') {
        $options = pop(@_);
 }

 my @dirs = @_;
 my @results;

 for my $file (@dirs){
	my $conn = $self->_get_connection || return;
	$self->_send($conn, "$cmd $file\n");

	for my $result ($conn->getline){
		chomp($result);

		my @result = split(/\s/, $result);

		chomp(my $code = pop @result);
		if($code !~ /^(?:ERROR|FOUND|OK)$/){
			$conn->close;

			return $self->_seterrstr("Unknown response code from ClamAV service: $code - " . join(" ", @result));
		}

		my $virus = pop @result;
		my $file = join(" ", @result);
		$file =~ s/:$//g;

		if($code eq 'ERROR'){
			$conn->close;

			return $self->_seterrstr("Error while processing file: $file $virus");
		} elsif($code eq 'FOUND'){
			push @results, [$file, $virus, $code];
		}
	}

	$conn->close;
 }

 return @results;
}

sub _seterrstr {
 my ($self, $err) = @_;
 $self->{'.errstr'} = $err;
 return;
}

sub _send {
 my ($self, $fh, $data) = @_;
 return syswrite $fh, $data, length($data);
}

sub _get_connection {
 my ($self) = @_;
 if($self->{port} =~ /\D/){
	return $self->_get_unix_connection;
 } else {
	return $self->_get_tcp_connection;
 }
}

sub _get_tcp_connection {
 my ($self, $port) = @_;
 $port ||= $self->{port};

 return IO::Socket::INET->new(
	PeerAddr	=> 'localhost',
	PeerPort	=> $port,
	Proto		=> 'tcp',
	Type		=> SOCK_STREAM,
	Timeout		=> 10
 ) || $self->_seterrstr("Cannot connect to 'localhost:$port': $@");
}

sub _get_unix_connection {
 my ($self) = @_;
 return IO::Socket::UNIX->new(
	Type => SOCK_STREAM,
	Peer => $self->{port}
 ) || $self->_seterrstr("Cannot connect to unix socket '$self->{port}': $@");
}

1;
__END__

=head1 AUTHOR

Colin Faber <cfaber@fpsn.net> All Rights Reserved.

Originally based on the Clamd module authored by Matt Sergeant.

=head1 LICENSE

This is free software and may be used and distribute under terms of perl itself.

=cut
