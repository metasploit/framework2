
###############
##
#
#    Name: Xor.pm
#  Author: skape <mmiller [at] hick.org>
# Version: $Revision$
# License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
# Descrip:
#
#      This module provides an xor implementation that can be used to
#      encrypt the communication channel between the client and server.
#
#      Obviously this shouldn't be considered secure (hell...the key
#      is transmitted in plain text to the server).  It does, however, 
#      obfuscate plaintext and help to bypass IDS if necessary.
#
##
###############

use strict;
use Pex::Meterpreter::Packet;

package Def;

use constant TLV_TYPE_XOR_KEY => makeTlv(TLV_META_TYPE_UINT, 1);

package Pex::Meterpreter::Crypto::Xor;

sub new
{
	my $this  = shift;
	my $class = ref($this) || $this;
	my $self  = {};
	my ($initializer) = @{{@_}}{qw/initializer/};

	bless($self, $class);

	# Set the default xor key
	$self->setKey(key => $initializer);

	return $self;
}

#
# Set the xor key
#
sub setKey
{
	my $self = shift;
	my ($key) = @{{@_}}{qw/key/};

	# Generate a random xor key if we were not provided with one
	$key = int(rand(0xffffffff)) if (not defined($key));

	# Set the xor key
	$self->{'key'} = $key;
}

#
# Return the xor key
#
sub getKey
{
	my $self = shift;

	return $self->{'key'};
}

#
# Populates the negotiation request with values that are unique to this
# cryptographic implementation, namely the xor key.
#
sub populateNegotiateRequest
{
	my $self = shift;
	my ($packet) = @{{@_}}{qw/packet/};
	my @tlvs = (
		{
			type  => Def::TLV_TYPE_XOR_KEY,
			value => $self->getKey()
		},
	);

	# Append TLVs
	$$packet->addTlv(
			type  => Def::TLV_TYPE_CIPHER_NAME,
			value => "xor");

	$$packet->addTlvs(
			tlvs      => \@tlvs,
			groupType => Def::TLV_TYPE_CIPHER_PARAMETERS);

	return 1;
}

#
# Process the response sent back to the original negotiation request.  The xor
# implementation really has no need to do this, but things like DH negotiation
# might.
#
sub processNegotiateResponse
{
	my $self = shift;
	my ($packet) = @{{@_}}{qw/packet/};

	return 1;
}

#
# Encrypt the supplied buffer
#
sub encrypt
{
	my $self = shift;
	my ($buffer, $length) = @{{@_}}{qw/buffer length/};

	return $self->crypt(
			buffer => $buffer,
			length => $length);
}

#
# Decrypt the supplied buffer
#
sub decrypt
{
	my $self = shift;
	my ($buffer, $length) = @{{@_}}{qw/buffer length/};

	return $self->crypt(
			buffer => $buffer,
			length => $length);
}

#
# Encryption and decryption are the same operation for XOR, so we just do the
# stuff here
#
sub crypt
{
	my $self = shift;
	my ($buffer, $length) = @{{@_}}{qw/buffer length/};
	my $outBuffer = '';
	my $offset = 0;

	for ($offset = 0; $offset < $length; $offset += 4)
	{
		my $chunk = substr($buffer, $offset);

		# Pad nulls 
		$chunk     .= "\x00" x (4 - length($chunk));

		# XOR
		$chunk      = unpack("V", $chunk) ^ $self->{'key'};

		# Append
		$outBuffer .= pack("V", $chunk);
	}
	
	return $outBuffer;
}

1;
