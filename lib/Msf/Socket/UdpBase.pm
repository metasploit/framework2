
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

package Msf::Socket::UdpBase;
use strict;
use base 'Msf::Socket::SocketBase';

sub Raw {
  my $self = shift;
  $self->_PexCall('Raw', @_) if(@_);
  my $raw = $self->GetEnv('UdpSourceIp');
  return(1) if($raw);
  return($self->_PexCall('Raw'));
}
  
1;
