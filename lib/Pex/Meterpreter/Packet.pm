
###############
##
#
#    Name: Packet.pm
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
#      This module exports methods for interacting with meterpreter
#      style packets.  For the curious, meterpreter style packets look like:
#
#       ........8........16........24........32
#      [               length                ]   <- includes length field
#      [                type                 ]
# 
#                        ..
#
#      [               n TLVs                ]
#
#      A TLV takes on the exact same format as the packet, but, instead of the
#      value of the TLV being the packet's payload, it is specific to the TLVs
#      type.
#
##
###############

use strict;
require Exporter;

#
# Does anyone know of a way around this?  I'd like to be able to export
# constants globally.  I've seen rather hackish ways to do it, such as using
# eval on a 'use constant' statement, but I'd prefer to not have to do that.  If
# you know of a way, shoot me an E-mail.  My lame "workaround" is to just use
# some bogus 'Def' namespace.
#
# The goal is to export bareword constants in the global namespace.
#
package Def;

sub makeTlv
{
	my $type = shift;
	my $id   = shift;

	return $type | $id;
}

# Packet types
use constant PACKET_TYPE_REQUEST         => 0;
use constant PACKET_TYPE_RESPONSE        => 1;
use constant PACKET_TYPE_PLAIN_REQUEST   => 10;
use constant PACKET_TYPE_PLAIN_RESPONSE  => 11;

# TLV types
use constant TLV_META_TYPE_NONE          => 0;
use constant TLV_META_TYPE_STRING        => (1 << 16);
use constant TLV_META_TYPE_UINT          => (1 << 17);
use constant TLV_META_TYPE_RAW           => (1 << 18);
use constant TLV_META_TYPE_BOOL          => (1 << 19);
use constant TLV_META_TYPE_GROUP         => (1 << 30);
use constant TLV_META_TYPE_COMPLEX       => (1 << 31);

# Load Library flags
use constant LOAD_LIBRARY_FLAG_ON_DISK   => (1 << 0);
use constant LOAD_LIBRARY_FLAG_EXTENSION => (1 << 1);
use constant LOAD_LIBRARY_FLAG_LOCAL     => (1 << 2);

# TLVs
use constant TLV_TYPE_ANY                => makeTlv(TLV_META_TYPE_NONE,     0);
use constant TLV_TYPE_METHOD             => makeTlv(TLV_META_TYPE_STRING,   1);
use constant TLV_TYPE_REQUEST_ID         => makeTlv(TLV_META_TYPE_STRING,   2);
use constant TLV_TYPE_EXCEPTION          => makeTlv(TLV_META_TYPE_GROUP,    3);
use constant TLV_TYPE_RESULT             => makeTlv(TLV_META_TYPE_UINT,     4);

use constant TLV_TYPE_STRING             => makeTlv(TLV_META_TYPE_STRING,  10);
use constant TLV_TYPE_UINT               => makeTlv(TLV_META_TYPE_UINT,    11);
use constant TLV_TYPE_BOOL               => makeTlv(TLV_META_TYPE_BOOL,    12);

use constant TLV_TYPE_LENGTH             => makeTlv(TLV_META_TYPE_UINT,    25);
use constant TLV_TYPE_DATA               => makeTlv(TLV_META_TYPE_RAW,     26);
use constant TLV_TYPE_FLAGS              => makeTlv(TLV_META_TYPE_UINT,    27);

use constant TLV_TYPE_CHANNEL_ID         => makeTlv(TLV_META_TYPE_UINT,    50);
use constant TLV_TYPE_CHANNEL_TYPE       => makeTlv(TLV_META_TYPE_STRING,  51);
use constant TLV_TYPE_CHANNEL_DATA       => makeTlv(TLV_META_TYPE_RAW,     52);
use constant TLV_TYPE_CHANNEL_DATA_GROUP => makeTlv(TLV_META_TYPE_GROUP,   53);

use constant TLV_TYPE_EXCEPTION_CODE     => makeTlv(TLV_META_TYPE_UINT,   300);
use constant TLV_TYPE_EXCEPTION_STRING   => makeTlv(TLV_META_TYPE_STRING, 301);

use constant TLV_TYPE_LIBRARY_PATH       => makeTlv(TLV_META_TYPE_STRING, 400);
use constant TLV_TYPE_TARGET_PATH        => makeTlv(TLV_META_TYPE_STRING, 401);

use constant TLV_TYPE_CIPHER_NAME        => makeTlv(TLV_META_TYPE_STRING, 500);
use constant TLV_TYPE_CIPHER_PARAMETERS  => makeTlv(TLV_META_TYPE_GROUP,  501);

our @EXPORT = qw(
	PACKET_TYPE_REQUEST
	PACKET_TYPE_RESPONSE
	PACKET_TYPE_PLAIN_REQUEST
	PACKET_TYPE_PLAIN_RESPONSE

	TLV_META_TYPE_NONE
	TLV_META_TYPE_STRING
	TLV_META_TYPE_UINT
	TLV_META_TYPE_RAW
	TLV_META_TYPE_BOOL
	TLV_META_TYPE_GROUP
	TLV_META_TYPE_COMPLEX

	TLV_TYPE_ANY
	TLV_TYPE_METHOD
	TLV_TYPE_REQUEST_ID
	TLV_TYPE_EXCEPTION
	TLV_TYPE_RESULT
	TLV_TYPE_STRING
	TLV_TYPE_UINT
	TLV_TYPE_BOOL
	TLV_TYPE_LENGTH
	TLV_TYPE_DATA
	TLV_TYPE_FLAGS
	TLV_TYPE_CHANNEL_ID
	TLV_TYPE_CHANNEL_TYPE
	TLV_TYPE_CHANNEL_DATA
	TLV_TYPE_CHANNEL_DATA_GROUP
	TLV_TYPE_EXCEPTION_CODE
	TLV_TYPE_EXCEPTION_STRING
	TLV_TYPE_LIBRARY_PATH
	TLV_TYPE_TARGET_PATH
	TVL_TYPE_CIPHER_NAME
	TLV_TYPE_CIPHER_PARAMETERS

	makeTlv
);

package Pex::Meterpreter::Packet;

#
# Constructor
#
sub new
{
	my $this  = shift;
	my $class = ref($this) || $this;
	my $self  = {};
	my ($type, $method) = @{{@_}}{qw/type method/};

	bless($self, $class);

	# Reset the contents of the packet to a blank slate
	$self->reset();

	# Set the type if it's supplied.
	$self->{'type'} = $type if (defined($type));

	# If a method is supplied, set it.
	if (defined($method))
	{
		$self->addTlv(
				type  => Def::TLV_TYPE_METHOD, 
				value => $method);
	}

	# If the packet is a request, generate a request identifier
	if ((defined($type)) and
	    (($type == Def::PACKET_TYPE_REQUEST) or 
	     ($type == Def::PACKET_TYPE_PLAIN_REQUEST)))
	{
		my $rid = '';

		foreach (1..32)
		{
			$rid .= int(rand(10));
		}

		$self->addTlv(
				type  => Def::TLV_TYPE_REQUEST_ID,
				value => $rid);
	}

	return $self;
}

#
# Create a response packet from the request
#
sub createResponse
{
	my $self = shift;
	my $response;
	my $type;

	# Determine which type of response to send based on the request type
	$type = Def::PACKET_TYPE_RESPONSE if ($self->getType() == Def::PACKET_TYPE_REQUEST);
	$type = Def::PACKET_TYPE_PLAIN_RESPONSE if ($self->getType() == Def::PACKET_TYPE_PLAIN_REQUEST);
	
	$response = Pex::Meterpreter::Packet->new(type => $type);

	if (defined($response))
	{
		my $method = $self->getMethod();

		# Set the response message's method
		if (defined($method))
		{
			$response->setMethod(method => $method);
		}
		
		# Add the requestor's identification number
		$response->addTlv(
				type  => Def::TLV_TYPE_REQUEST_ID, 
				value => $self->getTlv(type => Def::TLV_TYPE_REQUEST_ID));
	}

	return $response;
}

#
# Resets the packet's contents
# 
sub reset
{
	my $self = shift;

	# Reset the header
	$self->{'type'}              = undef;
	$self->{'length'}            = undef;
	$self->{'header'}            = '';
	$self->{'headerLengthLeft'}  = 8;

	# Reset the payload
	$self->{'payload'}           = '';
	$self->{'payloadLength'}     = 0;
	$self->{'payloadLengthLeft'} = 0;
}

##
#
# TLVs
#
##

#
# Adds a TLV to the packet
#
sub addTlv 
{
	my $self = shift;
	my ($type, $value, $rawBuffer, $rawBufferLength) = @{{@_}}{qw/type value rawBuffer rawBufferLength/};
	my $rawTlvLength;
	my $rawTlv;

	# Use a default value of nothing if necessary
	$value = '' if (not defined($value));

	# If the value type is a string, ensure that it has a null terminator
	$value .= pack("c", 0) if ($type & Def::TLV_META_TYPE_STRING);

	# If the value type is a UINT, convert it to network byte order
	$value = pack("N", $value) if ($type & Def::TLV_META_TYPE_UINT);

	# If the value type is a BOOL, take only the first raw byte
	$value = pack("c", substr($value, 0, 1)) if ($type & Def::TLV_META_TYPE_BOOL);

	# Calculate the length of the TLV
	$rawTlvLength = length($value) + 8;

	# Build the raw TLV
	$rawTlv  = pack("NN", $rawTlvLength, $type);
	$rawTlv .= $value;

	# Append the raw TLV to the supplied buffer, or, by default, the packet's
	# payload
	if (defined($rawBuffer) and defined($rawBufferLength))
	{
		$$rawBuffer       .= $rawTlv;	
		$$rawBufferLength += $rawTlvLength;
	}
	else
	{
		$self->{'payload'}       .= $rawTlv;
		$self->{'payloadLength'} += $rawTlvLength;
	}
}

#
# Adds an array of TLVs, optionally to a group 
#
sub addTlvs
{
	my $self = shift;
	my ($tlvs, $groupType) = @{{@_}}{qw/tlvs groupType/};
	my $rawBufferLength = 0;
	my $rawBuffer;

	# Enumerate through all the TLVs, adding each one to the output buffer
	foreach my $tlv (@{ $tlvs })
	{
		$self->addTlv(
				type            => $tlv->{'type'},
				value           => $tlv->{'value'},
				rawBuffer       => \$rawBuffer,
				rawBufferLength => \$rawBufferLength);
	}

	# If a group type was defined, add the buffer as being of the given type
	# rather than simply concatenating it to the payload
	if (defined($groupType))
	{
		$self->addTlv(
				type  => $groupType,
				value => $rawBuffer);
	}
	else
	{
		$self->{'payload'}       .= $rawBuffer;
		$self->{'payloadLength'} += $rawBufferLength;
	}
}

#
# Enumerate the list of TLVs in the packet at a given index
#
sub enumTlv
{
	my $self = shift;
	my ($type, $index, $buffer) = @{{@_}}{qw/type index buffer/};
	my $currentOffset = 0;
	my $currentIndex = 0;
	my $currentValue = undef;
	my $currentLength;
	my $bufferLength;
	my $currentType;

	# Default to index 0
	$index  = 0 if (not defined($index));

	# Default to the packet's payload if no buffer is supplied
	$buffer       = $self->{'payload'} if (not defined($buffer));
	$bufferLength = length($buffer);

	while ((($currentOffset + 8) <= $bufferLength) and
	       (not defined($currentValue)))
	{
		($currentLength, $currentType) = unpack("NN", substr($buffer, $currentOffset, 8));

		# Sanity check
		last if ($currentLength + $currentOffset > $bufferLength);

		# If a type was supplied and this TLV's type does not match, continue
		if ((defined($type)) and ($type ne $currentType))
		{
			$currentOffset += $currentLength;
			next;
		}

		# If an index was supplied and the current index for this type does not
		# match, continue
		if ($currentIndex < $index)
		{
			$currentOffset += $currentLength;
			$currentIndex++;
			next;	
		}

		# If we get here, we're where we want to be...a matching type/index
		$currentValue = substr($buffer, $currentOffset + 8, $currentLength - 8);

		# Do some type conversions based on the meta type of the value
		$currentValue = unpack("N", $currentValue) if ($currentType & Def::TLV_META_TYPE_UINT);

		# If the value is a string, chop of the null terminator as we don't need
		# it in perl land.
		$currentValue = substr($currentValue, 0, length($currentValue) - 1) if ($currentType & Def::TLV_META_TYPE_STRING);
	}

	# Return the determined value, if any.
	return $currentValue;
}

#
# Gets the value of the first instance of a TLV
#
sub getTlv
{
	my $self = shift;
	my ($type, $buffer) = @{{@_}}{qw/type buffer/};

	return $self->enumTlv(
			type   => $type,
			buffer => $buffer);
}

##
#
# Getters/Setters
#
##

#
# Gets the packet's type (PACKET_TYPE_XXX)
#
sub getType
{
	my $self = shift;

	return $self->{'type'};
}

#
# Sets the packet's type (PACKET_TYPE_XXX)
# 
sub setType
{
	my $self = shift;
	my ($type) = @{{@_}}{qw/type/};

	$self->{'type'} = $type;
}

# 
# Gets the length of the packet
#
sub getLength
{
	my $self = shift;

	return $self->{'length'};
}

#
# Sets the packet.s method.  This should only be called once.
#
sub setMethod
{
	my $self = shift;
	my ($method) = @{{@_}}{qw/method/};

	return $self->addTlv(type => Def::TLV_TYPE_METHOD, value => $method);
}

#
# Gets the packet's method.
#
sub getMethod
{
	my $self = shift;

	return $self->getTlv(type => Def::TLV_TYPE_METHOD);
}

#
# Get the packet's result TLV (TLV_TYPE_RESULT)
#
sub getResult
{
	my $self = shift;

	return $self->getTlv(type => Def::TLV_TYPE_RESULT);
}

##
#
# Network I/O
#
##

#
# Reads data from the supplied file descriptor.  If a complete packet is read
# in, 1 is returned to indicate that it is ready to be processed.  If an error
# occurs, or the packet is malformed, -1 is returned.  0 is an indication that
# the entire packet has yet to be read.
#
sub recv
{
	my $self = shift;
	my ($fd, $cipher) = @{{@_}}{qw/fd cipher/};
	my $tempBufferLength;
	my $tempBuffer;
	my $inHeader;
	my $res = 0;

	# If there is data still left to be read from the header, we shall read just
	# that amount.
	if ($self->{'headerLengthLeft'} > 0)
	{
		$tempBufferLength = $self->{'headerLengthLeft'};
		$inHeader         = 1;
	}
	elsif ($self->{'payloadLengthLeft'} > 0)
	{
		$tempBufferLength = $self->{'payloadLengthLeft'};
		$inHeader         = 0;
	}
	else
	{
		$res = -1;
	}

	# Read in some stuff
	$res -1 if ($res >= 0 and not defined(recv($fd, $tempBuffer, $tempBufferLength, 0))); 

	#print STDERR "Wanted $tempBufferLength, read " . length($tempBuffer) . "\n";

	# If we had a valid read...
	if ($res >= 0)
	{
		# If we were reading part of the header...
		if ($inHeader)
		{
			$self->{'header'}           .= $tempBuffer;
			$self->{'headerLengthLeft'} -= length($tempBuffer);

			# If the full header has been read...
			if ($self->{'headerLengthLeft'} == 0)
			{
				($self->{'length'}, $self->{'type'}) = unpack("NN", $self->{'header'});

				# If the packet length is claimed to be less than or equal to eight,
				# bomb out.
				if ($self->{'length'} <= 8)
				{
					$res = -1;
				}
				else
				{
					$self->{'payloadLengthLeft'} = $self->{'length'} - 8;
				}
			}
		}
		else
		{
			$self->{'payload'}           .= $tempBuffer;
			$self->{'payloadLengthLeft'} -= length($tempBuffer);

			# If there are no more bytes of the payload left to read, we have read
			# the entire packet and are ready to process it.
			$res = 1 if ($self->{'payloadLengthLeft'} == 0);
		}
	}

	# If the entire packet has been read...
	if ($res == 1)
	{
		# If a cipher was supplied and the packet is not a plaintext packet,
		# decrypt it
		if ((defined($cipher)) and
		    ($self->{'type'} != Def::PACKET_TYPE_PLAIN_REQUEST) and
		    ($self->{'type'} != Def::PACKET_TYPE_PLAIN_RESPONSE))
		{
			my $plainPayload = $$cipher->decrypt(
					buffer => $self->{'payload'},
					length => $self->{'length'} - 8);

			# Update the payload buffer & packet length
			$self->{'payload'} = $plainPayload;
			$self->{'length'}  = length($plainPayload) + 8;
		}
	}

	return $res;
}

#
# Transmits a packet to the supplied file descriptor
#
sub transmit
{
	my $self = shift;
	my ($fd, $cipher) = @{{@_}}{qw/fd cipher/};
	my $payloadLength = $self->{'payloadLength'};
	my $payload = $self->{'payload'};
	my $packetLength;
	my $header;
	my $res = 0;

	# If a cipher was supplied and the packet is not a plaintext packet
	if ((defined($cipher)) and
	    ($self->{'type'} != Def::PACKET_TYPE_PLAIN_REQUEST) and
	    ($self->{'type'} != Def::PACKET_TYPE_PLAIN_RESPONSE))
	{
		$payload = $$cipher->encrypt(
				buffer => $payload,
				length => $payloadLength);

		$payloadLength = length($payload);
	}

	# Calculate the packet length and initialize the header buffer
	$packetLength = $payloadLength + 8;
	$header       = pack("NN", $packetLength, $self->{'type'});

	# Transmit the header
	$res = -1 if (not defined($self->writeFull(
			fd     => $fd, 
			buf    => $header,
			length => 8)));

	# Transmit the payload
	$res = -1 if (($res >= 0) and (not defined($self->writeFull(
			fd     => $fd, 
			buf    => $payload,
			length => $payloadLength))));

	return $res;
}

#
# Write the entire contents of the buffer to the wire
#
sub writeFull
{
	my $self = shift;
	my ($fd, $buf, $length) = @{{@_}}{qw/fd buf length/};
	my $offset = 0;
	my $left = $length;
	my $sent;

	while ($offset < $length)
	{
		$sent = syswrite($fd, substr($buf, $offset, $left), $left, 0);

		if (not defined($sent))
		{
			$offset = -1;

			last;
		}

		$offset += $sent;
		$left   -= $sent;
	}

	return $offset;
}

1;
