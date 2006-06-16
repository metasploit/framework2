###############
##
#
#    Name: ReverseStager.pm
# Version: $Revision$
# License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
# Descrip:
#
#      Architecture independent reverse stager base class for OSX.
#
##
###############

package Msf::PayloadComponent::OSX::ReverseStager;

use strict;
use base 'Msf::PayloadComponent::OSX::Payload';
use vars qw{@ISA};

#
# Dynamically inherit Payload from ReverseConnection
#
sub _Load
{
	Msf::PayloadComponent::OSX::Payload->_Import('Msf::PayloadComponent::ReverseConnection');

	__PACKAGE__->SUPER::_Load();
}

1;
