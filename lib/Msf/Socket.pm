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

  my $proxies = $self->GetVar('Proxies');

  foreach (split(',', $proxies)) {
    $self->AddProxy(split(':', $_));
    return if($self->PrintError);
  }
}

sub UseSSL {
  my $self = shift;
  my $ssl = $self->GetLocal('ForceSSL');
  $ssl = $self->SUPER::UseSSL if(!defined($ssl));
  return($ssl);
}

sub GetConnectTimeout {
  my $self = shift;
  my $timeout = $self->GetLocal('ConnectTimeout');
  $timeout = $self->SUPER::GetConnectTimeout if(!defined($timeout));
  return($timeout);
}

sub GetRecvTimeout {
  my $self = shift;
  my $timeout = $self->GetLocal('RecvTimeout');
  $timeout = $self->SUPER::GetRecvTimeout if(!defined($timeout));
  return($timeout);
}

sub GetRecvTimeoutLoop {
  my $self = shift;
  my $timeout = $self->GetLocal('RecvTimeoutLoop');
  $timeout = $self->SUPER::GetRecvTimeoutLoop if(!defined($timeout));
  return($timeout);
}

1;
