###############
##
#
#    Name: BindStager.pm
# Version: $Revision$
# License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
# Descrip:
#
#      Architecture independent bind stager base class for Linux.
#
##
###############

package Msf::PayloadComponent::Linux::BindStager;

use strict;
use base 'Msf::PayloadComponent::Linux::Payload';
use vars qw{@ISA};

#
# Dynamically inherit Payload from BindConnection
#
sub _Load
{
	Msf::PayloadComponent::Linux::Payload->_Import('Msf::PayloadComponent::BindConnection');

	__PACKAGE__->SUPER::_Load();
}

1;
