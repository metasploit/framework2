#!/usr/bin/perl
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
  print "Calling $method\n";
  return($self->$method(@_));
}


#sub SSL {
#  my $self = shift;
#  return($self->SUPER::SSL(@_)) if(@_);
#  my $ssl = $self->GetLocal('ForceSSL');
#  $ssl = $self->SUPER::SSL if(!defined($ssl));
#  return($ssl);
#}
#sub Timeout {
#  my $self = shift;
#  my $timeout = $self->GetLocal('ConnectTimeout');
#  $timeout = $self->SUPER::GetConnectTimeout if(!defined($timeout));
#  return($timeout);
#}

1;
