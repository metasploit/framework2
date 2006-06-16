
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

package Msf::Socket::SocketBase;
use strict;

sub _PexCall {
  my $self = shift;
  my $method = $self->_PexParent . '::' . shift;
  # print "Calling $method\n";
  return($self->$method(@_));
}

sub Timeout {
  my $self = shift;
  return($self->_PexCall('Timeout', @_)) if(@_);
  my $timeout = $self->GetVar('ConnectTimeout');
  $timeout = $self->_PexCall('Timeout') if(!defined($timeout));
  return($timeout);
}
sub RecvTimeout {
  my $self = shift;
  return($self->_PexCall('RecvTimeout', @_)) if(@_);
  my $timeout = $self->GetVar('RecvTimeout');
  $timeout = $self->_PexCall('RecvTimeout') if(!defined($timeout));
  return($timeout);
}
sub RecvLoopTimeout {
  my $self = shift;
  return($self->_PexCall('RecvLoopTimeout', @_)) if(@_);
  my $timeout = $self->GetVar('RecvLoopTimeout');
  $timeout = $self->_PexCall('RecvLoopTimeout') if(!defined($timeout));
  return($timeout);
}


1;
