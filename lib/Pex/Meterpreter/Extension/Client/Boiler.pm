
###############
##
#
#    Name: Sys.pm
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
#      This module serves as a boiler plate template for new client-side
#      meterpreter extensions.
#
##
###############

use strict;
use Pex::Meterpreter::Packet;

package Def;

#
# This is the base index for TLVs inside this extension
#
use constant BOILER_BASE                     => 47;
use constant TLV_TYPE_BOILER                 => makeTlv(TLV_META_TYPE_STRING, BOILER_BASE +  0);

package Pex::Meterpreter::Extension::Client::Boiler;

my $instance = undef;
my @handlers = 
(
	{
		identifier  => "Boiler",
		description => "Boiler plate commands",
		handler     => undef,
	},
	{
		identifier  => "dummy",
		description => "This is a dummy command.",
		handler     => \&dummy,
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

		$self->registerHandlers(client => $client);

		$instance = $self;
	}
	else
	{
		$self = $instance;
	}

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
# A dummy command
#
sub dummy
{
	my ($client, $console, $argumentsScalar) = @{{@_}}{qw/client console parameter/};

	return 1;
}

1;
