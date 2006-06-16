
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

package Msf::Socket::Tcp;
use strict;
use base 'Msf::Socket::TcpBase', 'Pex::Socket::Tcp', 'Msf::Module';
use Msf::Socket::SSLTcp;

sub _PexParent {
  my $self = shift;
  return('Pex::Socket::Tcp');
}

sub _newSSL {
  my $self = shift;
  return(Msf::Socket::SSLTcp->new(@_));
}


1;
