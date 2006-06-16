
###############

##
#         Name: Encoder.pm
#       Author: spoonm <ninjatools [at] hush.com>
#      Version: $Revision$
#  Description: Parent class for Payload Encoders, inherits from Module.
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Msf::Encoder;
$VERSION = 2.0;
use strict;
use base 'Msf::Module';

sub new {
  my $class = shift;
  my $hash = @_ ? shift : { };
  my $self = $class->SUPER::new($hash);
  return($self);
}

sub Encode {
  my $self = shift;
    
  my $rawshell = shift;
  my $badChars = shift;

  return($self->EncodePayload($rawshell, $badChars));
}

sub EncodePayload {
  return;
}

1;
