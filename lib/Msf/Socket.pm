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

package Msf::Socket;
$VERSION = 2.0;
use strict;
# fixme
# Msf::Module for GetLocal, etc, maybe this should change
use base 'Pex::Socket', 'Msf::Module';

sub Init {
  my $self = shift;
  $self->SUPER::Init;

  my $proxies = $self->GetVar{'Proxies'});

  foreach (split(',', $proxies)) {
    $self->AddProxy(split(':', $_));
    return if($self->PrintError);
  }
}

sub GetTimeout {
  my $self = shift;
  my $timeout = $self->GetLocal('SocketTimeout');
  $timeout = $self->SUPER::GetTimeout() if(!defined($timeout));
  return($timeout);
}

sub GetTimeoutLoop {
  my $self = shift;
  my $timeout = $self->GetLocal('SocketTimeoutLoop');
  $timeout = $self->SUPER::GetTimeoutLoop() if(!defined($timeout));
  return($timeout);
}

1;
