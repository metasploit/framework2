###############
##
#
#    Name: StagePayload.pm
# Version: $Revision$
# License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
# Descrip:
#
#      Base class for stager payload components that handles
#      the transmission of the stage payload.
#
##
###############

package Msf::PayloadComponent::BSDi::StagePayload;

use strict;
use vars qw{@ISA};

#
# Import dependencies
#
sub _Import 
{
	my $class = shift;

	@ISA = ();

	foreach (@_) 
	{
		eval("use $_");
		unshift(@ISA, $_);
	}
}

#
# Returns the stage payload attribute of the information that was passed in
#
sub StagePayload 
{
	my $self = shift;

	return $self->_Info->{'StagePayload'};
}

#
# Transmits the stage that we were handed such that it will be executed and
# all the lored's people will be happy
#
sub HandleConnection 
{
	my $self = shift;
	my $blocking;
	my $payload;
	my $sock;

	# Prepare yoself!
	$self->SUPER::HandleConnection;

	# Build out the stage
	$sock     = $self->PipeRemoteOut;
	$payload  = $self->BuildPayload($self->StagePayload);
	$blocking = $sock->blocking;

	$sock->blocking(1);

	# Transmit the stage to the remote side
	$self->PrintLine('[*] Sending Stage (' . length($payload) . ' bytes)');

	eval { $sock->send($payload); };

	$self->PrintDebugLine(3, '[*] Stage Sent.');

	$sock->blocking($blocking);
}

1;
