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
#      Architecture independent findrecv stager base class for Windows.
#
##
###############

package Msf::PayloadComponent::Windows::FindRecvStager;

use strict;
use base 'Msf::PayloadComponent::Windows::Payload';
use vars qw{@ISA};

#
# Dynamically inherit Payload from FindConnection
#
sub _Load
{
	Msf::PayloadComponent::Windows::Payload->_Import('Msf::PayloadComponent::FindConnection');

	__PACKAGE__->SUPER::_Load();
}

#
# Handle the child socket that's passed to us by dishing out the tag
#
sub ChildHandler
{
	my $self = shift;
	my $sock = shift;
	my $tag = substr($self->GetLocal('FINDTAG') . ("\x01" x 4), 0, 4);

	# Set the stage prefix to the tag we're using
	$self->StagePrefix($tag);

	$self->PipeRemoteIn($sock);
	$self->PipeRemoteOut($sock);

	$self->HandleConnection($sock);
}

1;
