
###############
##
#
#    Name: RemoteDispatch.pm
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
#      This module implements some of the core packet handlers that 
#      are used on the client such as channel interaction and crypto
#      interaction.
#
##
###############

package Pex::Meterpreter::RemoteDispatch;

use strict;
use Pex::Meterpreter::Packet;

#
# Registers all of the input handlers
#
sub registerHandlers
{
	my ($client) = @{{@_}}{qw/client/};
	my @handlers = (
		{
			identifier      => "core_console_write",
			requestHandler  => \&requestCoreConsoleWrite,
			responseHandler => undef,
		},
		{
			identifier      => "core_channel_open",
			requestHandler  => \&requestCoreChannelOpen,
			responseHandler => \&responseCoreChannelOpen,
		},
		{
			identifier      => "core_channel_write",
			requestHandler  => \&requestCoreChannelWrite,
			responseHandler => undef,
		},
		{
			identifier      => "core_channel_read",
			requestHandler  => \&requestCoreChannelRead,
			responseHandler => undef,
		},
		{
			identifier      => "core_channel_close",
			requestHandler  => \&requestCoreChannelClose,
			responseHandler => \&responseCoreChannelClose,
		},
		{
			identifier      => "core_channel_interact",
			requestHandler  => \&requestCoreChannelInteract,
			responseHandler => undef,
		},

		{
			identifier      => "core_crypto_negotiate",
			requestHandler  => undef,
			responseHandler => \&responseCoreCryptoNegotiate,
		},
	);

	# Enumerate through all the base handlers and register them
	foreach my $handler (@handlers)
	{
		$client->registerRemotePacketHandler(
				identifier      => $handler->{'identifier'},
				requestHandler  => $handler->{'requestHandler'},
				responseHandler => $handler->{'responseHandler'});
	}

	return 1;
}

##
# 
# The packet handlers themselves.
#
##

sub requestCoreConsoleWrite
{
	my ($client, $packet) = @{{@_}}{qw/client parameter/};
	my $console = $client->getConsoleOutput();
	my $index = 0;
	my $string;

	$client->writeConsoleOutput(
			text => "\n");

	while (defined($string = $$packet->enumTlv(
			type  => Def::TLV_TYPE_STRING, 
			index => $index++)))
	{
		$client->writeConsoleOutput(
				text => $string);
	}

	$client->printPrompt();

}

##
#
# Cryptography
#
##

#
# Handles cryptographic negotiations
#
sub responseCoreCryptoNegotiate
{	
	my ($client, $packet) = @{{@_}}{qw/client parameter/};
	my $cipher = $client->getCipher();

	if (defined($cipher))
	{
		$$cipher->processNegotiateResponse(
				packet => $packet);
	}

	return 1;
}

##
#
# Channel related handlers
#
##

#
# Handles channel allocations
#
sub requestCoreChannelOpen
{	
	my ($client, $packet) = @{{@_}}{qw/client parameter/};
	my $response = $$packet->createResponse();
	my $channel = Pex::Meterpreter::Channel->new();

	$response->addTlv(
			type  => Def::TLV_TYPE_CHANNEL_ID,
			value => $channel->getId());

	# Transmit the response with the message identifier of the newly created
	# channel
	$client->transmitPacket(
			packet => \$response);

	return 1;
}

sub responseCoreChannelOpen
{	
	my ($client, $packet) = @{{@_}}{qw/client parameter/};
	my $channel;
	my $id;

	$id = $$packet->getTlv(	
			type => Def::TLV_TYPE_CHANNEL_ID);

	$channel = Pex::Meterpreter::Channel->new(id => $id);
	
	return 1;
}

#
# Handles requests to read from the channel supplied
#
sub requestCoreChannelRead
{
	my ($client, $packet) = @{{@_}}{qw/client parameter/};
	my $channel;
	my $length;
	my $buf;
	my $id;

	$length = $$packet->getTlv(
			type => Def::TLV_TYPE_LENGTH);
	$id = $$packet->getTlv(
			type => Def::TLV_TYPE_CHANNEL_ID);

	# Try to find the channel supplied by identifier
	if (not defined($channel = Pex::Meterpreter::Channel::find(id => $id)))
	{
		goto out;
	}

	$buf = $$channel->readFromLocal(length => $length);

	# Write the contents to the remote endpoint
	$$channel->write(
			client => $client,
			buffer => $buf,
			length => $length);

out:
	return 1;
}

#
# Handles requests to write to the channel supplied
#
sub requestCoreChannelWrite
{
	my ($client, $packet) = @{{@_}}{qw/client parameter/};
	my $channel;
	my $data;
	my $id;

	$id = $$packet->getTlv(
			type => Def::TLV_TYPE_CHANNEL_ID);
	$data = $$packet->getTlv(
			type => Def::TLV_TYPE_CHANNEL_DATA);

	# Try to find the channel supplied by identifier
	if (not defined($channel = Pex::Meterpreter::Channel::find(id => $id)))
	{
		goto out;
	}

	my $interactive = $client->getInteractiveChannel();

	if (defined($interactive) and ($$interactive == $$channel))
	{
		$client->writeConsoleOutput(
				text => $data);
	}
	else
	{
		# Write the supplied buffer to our local channel buffer
		$$channel->writeToLocal(
				buffer => $data,
				length => length($data));
	}
	
out:
	return 1;
}

#
# Handles requests to close the channel supplied
#
sub requestCoreChannelClose
{
	my ($client, $packet) = @{{@_}}{qw/client parameter/};
	my $response;
	my $channel;
	my $id;

	$id = $$packet->getTlv(
			type => Def::TLV_TYPE_CHANNEL_ID);

	# Try to find the channel supplied by identifier
	if (not defined($channel = Pex::Meterpreter::Channel::find(id => $id)))
	{
		goto out;
	}
	else
	{
		my $interactive = $client->getInteractiveChannel();

		if (defined($interactive) and ($$interactive == $$channel))
		{
			$client->setInteractiveChannel(channel => undef);

			$client->writeConsoleOutput(text =>
					"\n" . 
					"interact: Ending interactive session.\n");
			$client->printPrompt();
		}
	}

	# Create the response and add the channel's identifier
	$response = $$packet->createResponse();

	$response->addTlv(
			type  => Def::TLV_TYPE_CHANNEL_ID,
			value => $id);

	# Destroy the channel
	$$channel->destroy();

out:
	return 1;
}

sub responseCoreChannelClose
{
	my ($client, $packet) = @{{@_}}{qw/client parameter/};
	my $channel;
	my $id;

	$id = $$packet->getTlv(
			type => Def::TLV_TYPE_CHANNEL_ID);

	# Try to find the channel supplied by identifier
	if (not defined($channel = Pex::Meterpreter::Channel::find(id => $id)))
	{
		goto out;
	}

	# Destroy the channel
	$$channel->destroy();

out:
	return 1;
}

#
# Handles request to set the interactive flag for the given channel
#
sub requestCoreChannelInteract
{
	my ($client, $packet) = @{{@_}}{qw/client parameter/};
	my $channel;
	my $enable;
	my $id;

	$id = $$packet->getTlv(
			type => Def::TLV_TYPE_CHANNEL_ID);
	$enable = $$packet->getTlv(
			type => Def::TLV_TYPE_BOOL);

	# Try to find the channel supplied by identifier
	if (not defined($channel = Pex::Meterpreter::Channel::find(id => $id)))
	{
		goto out;
	}

	$$channel->setInteractive(interactive => $enable);

out:
	return 1;
}

1;
