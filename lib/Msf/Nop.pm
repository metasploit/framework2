#!/usr/bin/perl
###############

##
#         Name: Nop.pm
#       Author: spoonm
#      Version: $Revision$
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Msf::Nop;
$VERSION = 2.0;
use strict;
use base 'Msf::Module';

my $defaults =
{
  'Name'        => 'No Name',
  'Version'     => '0.0',
  'Author'      => 'No Author',
  'Arch'        => [ ],
  'Refs'        => [ ],
  'Description' => 'No Description',
};

sub new {
  my $class = shift;
  my $hash = @_ ? shift : { };
  my $self = bless($hash, $class);
  $self->SetDefaults($defaults);
  $self->{'Exploit'} = shift;
  $self->{'Payload'} = shift;
  return($self);
}

sub _Exploit {
  my $self = shift;
  $self->{'Exploit'} = shift if(@_);
  return($self->{'Exploit'});
}
sub _Payload {
  my $self = shift;
  $self->{'Payload'} = shift if(@_);
  return($self->{'Payload'});
}

sub Nops {
  return;
}

1;
