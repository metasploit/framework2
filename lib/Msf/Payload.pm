#!/usr/bin/perl
###############

##
#         Name: Payload.pm
#       Author: spoonm <ninjatools [at] hush.com>
#      Version: $Revision$
#  Description: Parent class for Payloads, inherits from Module.
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Msf::Payload;
use strict;
use base 'Msf::Module';

my $defaults =
{
  'Multistage'  => 0,
  'Type'        => '',
  'Size'        => 0,
};

sub new {
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash->{'_InfoDefaults'} = $defaults;
  my $self = $class->SUPER::new($hash);
  return($self);
}

sub Type        { my $self = shift; return $self->_Info->{'Type'}; }
sub Size        { my $self = shift; return $self->_Info->{'Size'}; }
sub Multistage  { my $self = shift; return $self->_Info->{'Multistage'}; }

sub Loadable {
  my $self = shift;
  return($self->Size > 0);
}

# Fall throughs
sub Build {
  my $self = shift;
  return($self->Generate);
}

sub Generate {
  my $self = shift;
  $self->PrintLine('[*] No Generate for this payload: ' , $self->SelfName);
  return;
}

1;
