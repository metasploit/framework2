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

package Msf::Socket::TcpBase;
use strict;
use base 'Msf::Socket::SocketBase';

sub Init {
  my $self = shift;
  $self->_PexCall('Init');
  my $proxies = $self->GetVar('Proxies');
  if ($proxies) {
    print "Proxies $proxies\n";
    foreach (split(',', $proxies)) {
      $self->AddProxy(split(':', $_));
      return if($self->IsError);
    }
  }
}

sub SSL {
  my $self = shift;
  return($self->SUPER::SSL(@_)) if(@_);
  my $ssl = $self->GetVar('ForceSSL');
  $ssl = $self->SUPER::SSL if(!defined($ssl));
  return($ssl);
}


1;
