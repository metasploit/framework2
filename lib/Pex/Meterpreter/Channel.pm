
###############
##
#
#    Name: Channel.pm
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
#      This module provides an interface for interacting with channels
#      (think file descriptors).  These channels allow the server and
#      client to write and read data between one another in an asynchronous
#      or synchronous fashion depending on how the I/O handlers are 
#      implemented.
#
##
###############

use strict;
use Pex::Meterpreter::Packet;
require Exporter;

package Def;

use constant CHANNEL_DIO_MODE_OPEN       => 0;
use constant CHANNEL_DIO_MODE_READ       => 1;
use constant CHANNEL_DIO_MODE_WRITE      => 2;
use constant CHANNEL_DIO_MODE_CLOSE      => 3;
use constant CHANNEL_DIO_MODE_INTERACT   => 4;

our @EXPORT = qw(
	CHANNEL_DIO_MODE_OPEN
	CHANNEL_DIO_MODE_READ
	CHANNEL_DIO_MODE_WRITE
	CHANNEL_DIO_MODE_CLOSE
	CHANNEL_DIO_MODE_INTERACT
);

package Pex::Meterpreter::Channel;

#
# Global channel id pool and list for tracking channels
#
my $channelIds  = 0;
my @channelList = ();

#
# Constructor -- optionally accepting a channel identifier
#
sub new
{
	my $this  = shift;
	my $class = ref($this) || $this;
	my ($id)  = @{{@_}}{qw/id/};
	my $self  = {};

	$id = ++$channelIds if (not defined($id));

	# Initialize attributes
	$self->{'id'}                = $id;
	$self->{'type'}              = undef;
	$self->{'interactive'}       = 0;

	$self->{'localBuffer'}       = '';
	$self->{'localIoHandler'}    = \&Pex::Meterpreter::Channel::defaultIoHandler;
	$self->{'localIoHandlerCtx'} = undef;

	bless($self, $class);

	# Push ourself into the list of channels
	push @channelList, \$self;

	return $self;
}

#
# Pseudo-destructor (used to remove the channel from the channel list
#
sub destroy
{
	my $self = shift;
	my $idx = 0;

	foreach my $c (@channelList)
	{
		if ($$c->getId() == $self->getId())
		{
			splice @channelList, $idx, 1;
			last;
		}

		$idx++;
	}
}

#
# Tries to locate a channel by its identifier
#
sub find
{
	my ($id) = @{{@_}}{qw/id/};
	my $channel;

	foreach my $c (@channelList)
	{
		if ($$c->getId() == $id)
		{
			$channel = $c;
			last;
		}
	}

	return $channel;
}

##
# 
# Getters/Setters
#
##

#
# Get the channel's identifier
#
sub getId
{
	my $self = shift;

	return $self->{'id'};
}

#
# Set the channel's type
#
sub setType
{
	my $self = shift;
	my ($type) = @{{@_}}{qw/type/};

	$self->{'type'} = $type;
}

#
# Get the channel's type
#
sub getType
{
	my $self = shift;

	return $self->{'type'};
}

#
# Set the channel's interactive flag
#
sub setInteractive
{
	my $self = shift;
	my ($interactive) = @{{@_}}{qw/interactive/};

	$self->{'interactive'} = $interactive;
}

#
# Get the channel's interactive flag
#
sub getInteractive
{
	my $self = shift;

	return $self->{'interactive'};
}

##
#
# Buffer management
#
##

#
# Writes the supplied buffer to the end of the local buffer and returns the
# number of bytes written.
#
sub writeToLocal
{
	my $self = shift;
	my ($buffer, $length) = @{{@_}}{qw/buffer length/};

	return &{ $self->{'localIoHandler'} }(
			channel => \$self,
			context => $self->{'localIoHandlerCtx'},
			mode    => Def::CHANNEL_DIO_MODE_WRITE,
			buffer  => $buffer,
			length  => $length);
}

#
# Reads the supplied number of bytes from the local buffer and returns them.
#
sub readFromLocal
{
	my $self = shift;
	my ($length) = @{{@_}}{qw/length/};
	my $res;

	return &{ $self->{'localIoHandler'} }(
			channel => \$self,
			context => $self->{'localIoHandlerCtx'},
			mode    => Def::CHANNEL_DIO_MODE_READ,
			length  => $length);
}

##
#
# I/O
#
##

#
# Opens a new channel with the remote endpoint
#
sub open
{
	my ($client, $addends, $completionHandler, $completionHandlerParameter) = @{{@_}}{qw/client addends completionHandler completionHandlerParameter/};
	my $request;

	# Create the core_channel_open request
	$request = Pex::Meterpreter::Packet->new(
			type   => Def::PACKET_TYPE_REQUEST);

	# If addends have been supplied, add them to the request
	if (defined($addends))
	{
		$request->addTlvs(
				tlvs => $addends);
	}

	# If no method is defined, set it to the default
	if (not defined($request->getTlv(
			type => Def::TLV_TYPE_METHOD)))
	{
		$request->setMethod(method => "core_channel_open");
	}

	# Build the completion handler parameter array
	my @handlerParameters;
	push @handlerParameters, $completionHandler;
	push @handlerParameters, $completionHandlerParameter;

	# Transmit the request packet
	$client->transmitPacket(
			packet                     => \$request,
			completionHandler          => \&channelPacketCompletionRoutine,
			completionHandlerParameter => \@handlerParameters);

	return 1;
}

#
# Reads data from the remote channel endpoint
#
sub read
{
	my $self = shift;
	my ($client, $length, $addends, $completionHandler, $completionHandlerParameter) = @{{@_}}{qw/client length addends completionHandler completionHandlerParameter/};
	my $request;
	
	# Create the core_channel_read request
	$request = Pex::Meterpreter::Packet->new(
			type   => Def::PACKET_TYPE_REQUEST,
			method => "core_channel_read");

	# If addends have been supplied, add them to the request
	if (defined($addends))
	{
		$request->addTlvs(
				tlvs => $addends);
	}

	# Add TLVs
	$request->addTlv(
			type  => Def::TLV_TYPE_CHANNEL_ID,
			value => $self->getId());
	$request->addTlv(
			type  => Def::TLV_TYPE_LENGTH,
			value => $length);

	# Build the completion handler parameter array
	my @handlerParameters;
	push @handlerParameters, $completionHandler;
	push @handlerParameters, $completionHandlerParameter;

	# Transmit the request packet
	$client->transmitPacket(
			packet                     => \$request,
			completionHandler          => \&channelPacketCompletionRoutine,
			completionHandlerParameter => \@handlerParameters);

	return 1;
}

#
# Writes data to the remote channel endpoint
#
sub write
{
	my $self = shift;
	my ($client, $buffer, $length, $addends, $completionHandler, $completionHandlerParameter) = @{{@_}}{qw/client buffer length addends completionHandler completionHandlerParameter/};
	my $request;

	$length = length($buffer) if (not defined($length));
	
	# Create the core_channel_read request
	$request = Pex::Meterpreter::Packet->new(
			type   => Def::PACKET_TYPE_REQUEST,
			method => "core_channel_write");

	# If addends have been supplied, add them to the request
	if (defined($addends))
	{
		$request->addTlvs(
				tlvs => $addends);
	}

	# Add TLVs
	$request->addTlv(
			type  => Def::TLV_TYPE_CHANNEL_ID,
			value => $self->getId());
	$request->addTlv(
			type  => Def::TLV_TYPE_LENGTH,
			value => $length);
	$request->addTlv(
			type  => Def::TLV_TYPE_CHANNEL_DATA,
			value => $buffer);

	# Build the completion handler parameter array
	my @handlerParameters;
	push @handlerParameters, $completionHandler;
	push @handlerParameters, $completionHandlerParameter;

	# Transmit the request packet
	$client->transmitPacket(
			packet                     => \$request,
			completionHandler          => \&channelPacketCompletionRoutine,
			completionHandlerParameter => \@handlerParameters);

	return 1;
}

#
# Closes a channel
#
sub close
{
	my $self = shift;
	my ($client, $addends, $completionHandler, $completionHandlerParameter) = @{{@_}}{qw/client addends completionHandler completionHandlerParameter/};
	my $request;

	# Create the core_channel_read request
	$request = Pex::Meterpreter::Packet->new(
			type   => Def::PACKET_TYPE_REQUEST,
			method => "core_channel_close");

	# If addends have been supplied, add them to the request
	if (defined($addends))
	{
		$request->addTlvs(
				tlvs => $addends);
	}

	# Add TLVs
	$request->addTlv(
			type  => Def::TLV_TYPE_CHANNEL_ID,
			value => $self->getId());

	# Build the completion handler parameter array
	my @handlerParameters;
	push @handlerParameters, $completionHandler;
	push @handlerParameters, $completionHandlerParameter;

	# Transmit the request packet
	$client->transmitPacket(
			packet                     => \$request,
			completionHandler          => \&channelPacketCompletionRoutine,
			completionHandlerParameter => \@handlerParameters);

	return 1;
}

#
# Set the interactive flag on a remote channel endpoint, either enabling or
# disabling it.
#
sub interact
{
	my $self = shift;
	my ($client, $enable, $addends, $completionHandler, $completionHandlerParameter) = @{{@_}}{qw/client enable addends completionHandler completionHandlerParameter/};
	my $request;
	my $intchan;

	# If there is an interactive channel that is this channel and the user wants
	# us to disable interaction, do that now.
	if ((defined($intchan = $client->getInteractiveChannel())) and
	    ($$intchan == $self) and
	    ($enable == 0))
	{
		$client->setInteractiveChannel(channel => undef);
		$client->writeConsoleOutput(text => "\n");
		$client->printPrompt();
	}

	# Create the core_channel_read request
	$request = Pex::Meterpreter::Packet->new(
			type   => Def::PACKET_TYPE_REQUEST,
			method => "core_channel_interact");

	# If addends have been supplied, add them to the request
	if (defined($addends))
	{
		$request->addTlvs(
				tlvs => $addends);
	}

	# Add TLVs
	$request->addTlv(
			type  => Def::TLV_TYPE_CHANNEL_ID,
			value => $self->getId());
	$request->addTlv(
			type  => Def::TLV_TYPE_BOOL,
			value => $enable);

	# Build the completion handler parameter array
	my @handlerParameters;
	push @handlerParameters, $completionHandler;
	push @handlerParameters, $completionHandlerParameter;

	# Transmit the request packet
	$client->transmitPacket(
			packet                     => \$request,
			completionHandler          => \&channelPacketCompletionRoutine,
			completionHandlerParameter => \@handlerParameters);

	return 1;

}

##
#
# I/O Handling
#
##

#
# Sets the I/O handler for the channel
#
sub setLocalIoHandler
{
	my $self = shift;
	my ($handler, $context) = @{{@_}}{qw/handler context/};

	$self->{'localIoHandler'}    = $handler;
	$self->{'localIoHandlerCtx'} = $context;
	
	return 1;
}

#
# The default I/O handler for a channel.  It is used to internally queue data.
#
# Returns the number of bytes transferred, if any.
#
sub defaultIoHandler
{
	my ($channel, $context, $mode, $buffer, $length) = @{{@_}}{qw/channel context mode buffer length/};
	my $res = 0;

	$length = length($buffer) if (defined($buffer) and not defined($length));

	# If a read was requested, pop the front of the text for the specified number
	# of bytes off the front
	if ($mode == Def::CHANNEL_DIO_MODE_READ)
	{
		my $localBuffer = $$channel->{'localBuffer'};
		my $left;

		# Read the supplied number of bytes
		$length = length($localBuffer) if ($length > length($localBuffer));
		$left   = length($localBuffer) - $length;
		$res    = substr($localBuffer, 0, $length);

		# Move the remaining bytes down
		$$channel->{'localBuffer'} = substr($localBuffer, $length, $left);
	}
	elsif ($mode == Def::CHANNEL_DIO_MODE_WRITE)
	{
		$$channel->{'localBuffer'} .= substr($buffer, 0, $length);

		$res = $length;
	}
	
	return $res;
}

#
# The packet completion routine for all channel operations which dispatches to
# the appropriate handler
#
sub channelPacketCompletionRoutine
{
	my ($client, $packet, $parameter) = @{{@_}}{qw/client parameter handlerParameter/};
	my ($handler, $handlerParameter) = @{ $parameter };
	my $channel;
	my $method;
	my $res;
	my $id;

	# Get the packet's information
	$method = $$packet->getMethod();
	$res    = $$packet->getResult();
	$id     = $$packet->getTlv(
			type => Def::TLV_TYPE_CHANNEL_ID);

	# Lookup the channel
	$channel = Pex::Meterpreter::Channel::find(id => $id);

	# If there is no channel matching this identifier and the method is not
	# core_channel_open...
	if ((not defined($channel)) and ($method ne "core_channel_open"))
	{
		goto out;
	}

	if (defined($handler))
	{
		if ($method eq "core_channel_open")
		{
			# Call the open completion handler
			&{ $handler }(	
					client           => $client,
					channel          => $channel,
					result           => $res,
					handlerParameter => $handlerParameter);
		}
		elsif ($method eq "core_channel_read")
		{
			my $length = $$packet->getTlv(
					type => Def::TLV_TYPE_LENGTH);
			my $buf = $$channel->readFromLocal(length => $length);

			# Call the read completion handler
			&{ $handler }(	
					client           => $client,
					channel          => $channel,
					result           => $res,
					handlerParameter => $handlerParameter,
			      buffer           => $buf,
					length           => $length);

		}
		elsif ($method eq "core_channel_write")
		{
			my $length = $$packet->getTlv(
					type => Def::TLV_TYPE_LENGTH);

			# Call the write completion handler
			&{ $handler }(	
					client           => $client,
					channel          => $channel,
					result           => $res,
					handlerParameter => $handlerParameter,
					length           => $length);

		}
		elsif ($method eq "core_channel_close")
		{
			# Call the close completion handler
			&{ $handler }(	
					client           => $client,
					channel          => $channel,
					result           => $res,
					handlerParameter => $handlerParameter);
		}
		elsif ($method eq "core_channel_interact")
		{
			# Call the interact completion handler
			&{ $handler }(	
					client           => $client,
					channel          => $channel,
					result           => $res,
					handlerParameter => $handlerParameter);
		}

	}

out:
	return 1;
}

1;
