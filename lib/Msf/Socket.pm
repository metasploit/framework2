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

sub GetTimeout {
  my $self = shift;
  return($self->GetLocal('SocketTimeout'));
}

1;
