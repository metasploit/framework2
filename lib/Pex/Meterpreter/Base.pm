
###############
##
#
#    Name: Base.pm
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
#      This module exports methods used to register request/response
#      handlers for a given method as would be used during client and 
#      server communication.  This class is a base class for the Client
#      class.
#
##
###############

package Pex::Meterpreter::Base;

use strict;
use Pex::Meterpreter::Packet;
use Pex::Meterpreter::LocalDispatch;
use Pex::Meterpreter::RemoteDispatch;

#
# Base class constructor
#
sub new
{
	my $this = shift;
	my $self = @{{@_}}{qw/self/};

	if (not defined($self))
	{
		$self = {};
	}

	# Initialize local lists
	$self->{'remotePacketRequestDispatchTable'}    = ();
	$self->{'remotePacketResponseDispatchTable'}   = ();
	$self->{'remotePacketCompletionDispatchTable'} = ();
	$self->{'localInputDispatchTable'}             = ();

	# Register default handlers
	Pex::Meterpreter::LocalDispatch::registerHandlers(
			client => $self);
	Pex::Meterpreter::RemoteDispatch::registerHandlers(
			client => $self);

	return $self;
}

#
# Registers a handler that will process a specific method from a remote packet
#
sub registerRemotePacketHandler
{
	my $self = shift;
	my ($identifier, $requestHandler, $responseHandler) = @{{@_}}{qw/identifier requestHandler responseHandler/};

	# Register the request handler, if provided
	if (defined($requestHandler))
	{
		push (@{ $self->{'remotePacketRequestDispatchTable'} },
			{
				identifier  => $identifier,
				handler     => $requestHandler
			});
	}

	# Register the response handler, if provided
	if (defined($responseHandler))
	{
		push (@{ $self->{'remotePacketResponseDispatchTable'} },
			{
				identifier  => $identifier,
				handler     => $responseHandler
			});
	}
	
	return 1;
}

#
# Deregisters a handler for a packet method
#
sub deregisterRemotePacketHandler
{
	my $self = shift;
	my ($identifier) = @{{@_}}{qw/identifier/};

	$self->removeDispatchTableEntry(
			identifier    => $identifier,
			dispatchTable => $self->{'remotePacketRequestDispatchTable'});
	
	$self->removeDispatchTableEntry(
			identifier    => $identifier,
			dispatchTable => $self->{'remotePacketResponseDispatchTable'});

	return 1;
}

#
# Registers a local input handler that will process a command given on the
# console
#
sub registerLocalInputHandler
{
	my $self = shift;
	my ($identifier, $description, $handler) = @{{@_}}{qw/identifier description handler/};

	push (@{ $self->{'localInputDispatchTable'} },
		{
			identifier  => $identifier,
			description => $description,
			handler     => $handler
		});

	return 1;
}

#
# Enumerates entries in the local input dispatch table
#
sub enumerateLocalInputHandlers
{
	my $self = shift;
	my ($index) = @{{@_}}{qw/index/};
	my $count = 0;

	foreach my $handler (@{ $self->{'localInputDispatchTable'} })
	{
		return $handler if ($count++ == $index);
	}

	return undef;
}

#
# Deregisters a local input handler
#
sub deregisterLocalInputHandler
{
	my $self = shift;
	my ($identifier) = @{{@_}}{qw/identifier/};

	return $self->removeDispatchTableEntry(
			identifier    => $identifier,
			dispatchTable => $self->{'localInputDispatchTable'});
}

#
# Dispatches packets received from the remote endpoint
#
sub dispatchRemotePacket
{
	my $self = shift;
	my ($packet)  = @{{@_}}{qw/packet/};
	my $requestId = $$packet->getTlv(type => Def::TLV_TYPE_REQUEST_ID);
	my $method    = $$packet->getTlv(type => Def::TLV_TYPE_METHOD);
	my $table;
	my $res;

	# Determine the dispatch table to use
	if (($$packet->getType() == Def::PACKET_TYPE_RESPONSE) or
	    ($$packet->getType() == Def::PACKET_TYPE_PLAIN_RESPONSE))
	{
		$table = $self->{'remotePacketResponseDispatchTable'};
	}
	else
	{
		$table = $self->{'remotePacketRequestDispatchTable'};
	}

	# Otherwise, hand the packet off to the remote packet dispatch table
	$res = $self->processDispatchTable(
			identifier    => $method,
			parameter     => $packet,
			dispatchTable => $table);
			
	# If the packet has a request identifier, check to see if there is a 
	# completion handler associated with it.
	if (defined($requestId))
	{
		if (($res = $self->processDispatchTable(
				identifier    => $requestId,
				parameter     => $packet,
				dispatchTable => $self->{'remotePacketCompletionDispatchTable'})) > 0)
		{
			# Remove the entry from the dispatch table
			$self->removeDispatchTableEntry(
					identifier    => $requestId,
					dispatchTable => $self->{'remotePacketCompletionDispatchTable'});

			return 1;
		}
	}

	return $res;
}

# 
# Dispatches commands entered on the console
#
sub dispatchLocalInput
{
	my $self = shift;
	my ($command) = @{{@_}}{qw/command/};
	my @arguments = split(/ /, $command);
	my $console = $self->getConsoleOutput();
	my $res;

	return 1 if ($arguments[0] eq '');

	# XXX switch to builtin msf arg parsing (quoted strings, etc)

	$res = $self->processDispatchTable(
			identifier    => $arguments[0],
			parameter     => \@arguments,
			dispatchTable => $self->{'localInputDispatchTable'});

	print $console "invalid command\n" if ($res == 0);

	return $res;
}

#
# Transmits a packet to the remote endpoint
#
sub transmitPacket
{
	my $self = shift;
	my ($packet, $completionHandler, $completionHandlerParameter) = @{{@_}}{qw/packet completionHandler completionHandlerParameter/};
	my $requestId = $$packet->getTlv(type => Def::TLV_TYPE_REQUEST_ID);

	# If a completion handler is supplied, push it into the completion handler
	# list
	if ((defined($completionHandler)) and
	    (defined($requestId)))
	{
		push (@{ $self->{'remotePacketCompletionDispatchTable'} },
			{
				identifier       => $requestId,
				handler          => $completionHandler,
				handlerParameter => $completionHandlerParameter
			});
	}

	# Transmit the packet, optionall encrypting it with a cipher
	return $$packet->transmit(
			fd     => $self->getSocketOutput(),
			cipher => $self->getCipher());
}

##
#
# Internal methods
#
##

#
# Enumerate a dispatch table for a given identifier
#
sub processDispatchTable
{
	my $self = shift;
	my ($identifier, $parameter, $dispatchTable) = @{{@_}}{qw/identifier parameter dispatchTable/};
	my $console = $self->getConsoleOutput();
	my $res = 0;

	foreach my $entry (@{ $dispatchTable })
	{
		next if ($entry->{'identifier'} ne $identifier);

		my $handler = $entry->{'handler'};

		next if (not defined($handler));

		$res = &{ $handler }(
				client           => $self, 
				parameter        => $parameter, 
				handlerParameter => $entry->{'handlerParameter'}, 
				console          => $console);
	}

	return $res;
}

#
# Removes an item from a dispatch table
#
sub removeDispatchTableEntry
{
	my $self = shift;
	my ($identifier, $dispatchTable) = @{{@_}}{qw/identifier dispatchTable/};
	my $match = 0;
	my $idx = 0;

	foreach my $entry (@{ $dispatchTable })
	{
		# If this entry's identifier matches, remove it
		if ($identifier eq $entry->{'identifier'})
		{
			splice @{ $dispatchTable }, $idx, 1;

			$match = 1;
			
			last;
		}

		$idx++;
	}

	return $match;
}

1;
