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
#      Architecture independent findrecv stager base class for Linux.
#
##
###############

package Msf::PayloadComponent::Linux::FindRecvStager;

use strict;
use base 'Msf::PayloadComponent::Linux::Payload';
use vars qw{@ISA};

#
# Dynamically inherit Payload from FindRecvConnection
#
sub _Load
{
	Msf::PayloadComponent::Linux::Payload->_Import('Msf::PayloadComponent::FindRecvConnection');

	__PACKAGE__->SUPER::_Load();
}

1;
