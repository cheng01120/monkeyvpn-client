package Session;
use strict;
use warnings;
#use common::sense;

use AnyEvent;
use AnyEvent::Handle;


use MicroECC;
use MonkeyVPN;
use LZF;

sub new {
    my($class, @args) = @_;

	my $curve = MicroECC::secp256k1();
	my ($pubkey, $privkey) = MicroECC::make_key($curve);
	printf "pub key: %s\n", unpack('H*', $pubkey);
    return bless {
        no_delay => 1,
        timeout => 300,
        read_chunk_size => 4096,

		MAC => "",
		user => "",
		closed => 0,
		curve => $curve,

		pubkey  => $pubkey,
		privkey => $privkey,
		shared_secret => "",
        @args,
    }, $class;
}

sub run {
	my ($self) = @_;

	# setup handle
	$self->{handle} = new AnyEvent::Handle
		fh => $self->{fh},
		on_eof => sub {
			print "Client eof.\n";
			$self->shutdown;
		},
		on_error => sub {
			printf "Client error: %s\n", $_[2];
			$self->shutdown;
		};
	$self->make_shared_secret;
}

sub make_shared_secret {
	my ($self) = @_;

	# send my public key to client.
	$self->handle->push_write($self->pubkey);
	$self->handle->push_read( chunk => 64, sub {
			if(!MicroECC::valid_public_key($_[1], $self->{curve})) {
				print "Client public key is INVALID.\n";
				$self->shutdown;
				return;
			}

			# compute shared secret.
			my $secret = MicroECC::shared_secret($_[1], $self->privkey, $self->{curve});
			$self->{shared_secret} = $secret;

			# read username and password
			$self->read_credential;
		}
	);
}

sub read_credential {
	my ($self) = @_;
	$self->handle->push_read(chunk => 2, sub {
		my ($credential_len, $lzf) = unpack 'C2', $_[1];
		printf "Credential len: %d\n", $credential_len;

		# read MAC, username . '|' .  password.
		$self->handle->push_read( chunk => $credential_len, sub {
			# XOR decrypt the credential.
			MonkeyVPN::crypt_xor($_[1], $self->{shared_secret});
			my $MAC = substr $_[1], 0, 6;
			printf "remote MAC: %s ", join('', unpack('H*', $MAC));
			my ($user, $pass) = split /\|/, substr $_[1], 6;
			printf "user: %s, pass: %s\n", $user, $pass;

			$self->{MAC}  = $MAC;
			$self->{user} = $user;

			# authenticate user and send auth result.
			my $result = $self->authenticate($user, $pass);
			$self->handle->push_write(pack('C', $result));

			if(!$result) {
				$self->shutdown;
			}

			# start read packet.
			$self->read_packet_header;
		});
	});
}

sub read_packet_header {
	my ($self) = @_;
	$self->handle->push_read( chunk => 2, sub {
			my $body_len = unpack('n', $_[1]);
			$self->read_packet_body($body_len);
		}
	);
}

sub read_packet_body {
	my ($self, $body_len) = @_;
	$self->handle->push_read( chunk => $body_len, sub {
			MonkeyVPN::crypt_xor($_[1], $self->{shared_secret});
			my $decompressed = LZF::decompress($_[1]);
			$self->{tap_handle}->push_write($decompressed);

			# read next header.
			$self->read_packet_header;
		}
	);
}

sub authenticate {
	my ($self, $user, $pass) = @_;

	if($user eq "openwrt" && $pass eq "openwrt") {
		return 1;
	}
	else {
		return 0;
	}
}

sub shutdown {
	my ($self) = @_;
	print "Session shutdown.\n";
	$self->{handle}->destroy;
	$self->{closed} = 1;
}

# write data comes from local tap device to remote.
sub write {
	my ($self, $frame) = @_;

	# LZF compress the frame, then xor.
	{
		use bytes;
		my $compressed = LZF::compress($frame);
		my $len = length $compressed;

		MonkeyVPN::crypt_xor($compressed, $self->{shared_secret});
		$self->handle->push_write( pack('n', $len) );
		$self->handle->push_write($compressed);
	}

}

sub host    { shift->{host} }
sub port    { shift->{port} }
sub handle  { shift->{handle} }
sub pubkey  { shift->{pubkey} }
sub privkey { shift->{privkey} }

sub closed  { shift->{closed} }
sub MAC     { shift->{MAC} } # MAC address

1;
