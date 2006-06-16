
###############

##
#         Name: Socket.pm
#       Author: spoonm <ninjatools [at] hush.com>
#      Version: $Revision$
#  Description: Socket wrapper around Pex::Socket.
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Msf::Socket::Udp;
use strict;
use base 'Msf::Socket::UdpBase', 'Pex::Socket::Udp', 'Msf::Module';

sub _PexParent {
  my $self = shift;
  return('Pex::Socket::Udp');
}

sub _newRaw {
  use Msf::Socket::RawUdp;
  my $self = shift;
  return(Msf::Socket::RawUdp->new(@_));
}

1;
