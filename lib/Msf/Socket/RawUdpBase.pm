
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

package Msf::Socket::RawUdpBase;
use strict;
use base 'Msf::Socket::SocketBase';

sub LocalAddr {
  my $self = shift;
  $self->_PexCall('LocalAddr', @_) if(@_);
  my $src = $self->GetEnv('UdpSourceIp');
  return($src) if($src);
  return($self->_PexCall('LocalAddr'));
}

1;
