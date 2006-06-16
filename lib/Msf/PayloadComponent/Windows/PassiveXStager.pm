###############
##
#
#    Name: PassiveXStager.pm
# Version: $Revision$
# License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
# Descrip:
#
#      Architecture independent PassiveX stager base class for Windows.
#
##
###############

package Msf::PayloadComponent::Windows::PassiveXStager;

use strict;
use base 'Msf::PayloadComponent::Windows::Payload';
use FindBin qw{$RealBin};
use vars qw{@ISA};

#
# Dynamically inherit Payload from PassiveXConnection
#
sub _Load
{
	Msf::PayloadComponent::Windows::Payload->_Import('Msf::PayloadComponent::PassiveXConnection');

	__PACKAGE__->SUPER::_Load();
}

1;
