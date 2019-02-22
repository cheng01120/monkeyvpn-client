#!/usr/bin/perl -w
use common::sense;
use FindBin qw($Bin);
use lib "$Bin";

use AnyEvent;
use AnyEvent::Handle;
use AnyEvent::Socket;

use MonkeyVPN qw/tun_alloc/;
use Session;

my @sessions = ();
my $cv = AnyEvent->condvar;

my $tap_fh = tun_alloc("tap0");
die "Unable to open TAP device: $!" unless $tap_fh;

my $tap_handle; $tap_handle = new AnyEvent::Handle(
	fh => $tap_fh,
	on_error => sub {
		printf "TAP device error: %s\n", $_[2];
		$tap_handle->destroy;

		foreach my $sess(@sessions) {
			$sess->shutdown;
		}

		$cv->send;
	},
	on_read => sub {
		#printf "Read from tap: %s\n\n", unpack('H*', shift->rbuf);
		# Got 1 ethernet frame
		my $tap_handle = shift;
		my $frame = $tap_handle->{rbuf};
		$tap_handle->{rbuf} = "";

		my $is_multicast = 0;
		my $dest_MAC = substr $frame, 0, 6;
		if($dest_MAC eq "\x33\x33\x00\x00\x00\x16" || $dest_MAC eq "\xff\xff\xff\xff\xff\xff")
		{
			$is_multicast = 1;
		}

		my $pos = 0;
		while($pos < scalar @sessions) {
			my $sess = $sessions[$pos];

			if($sess->closed) {
				splice @sessions, $pos, 1;
				next;
			}

			if($sess->MAC eq $dest_MAC || $is_multicast) {
				$sess->write($frame);
				last;
			}

			$pos ++;
		}
	}, # on_read
);

tcp_server undef, 1226, sub {
	my ($fh, $host, $port) = @_;

	my $session = Session->new(
		tap_handle => $tap_handle, 
		host => $host, 
		port => $port, 
		fh => $fh
	);
	push @sessions, $session;
	$session->run;
};

$cv->recv;
