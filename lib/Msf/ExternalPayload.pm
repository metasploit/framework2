#!/usr/bin/perl
###############

##
#         Name: ExternalPayload.pm
#       Author: spoonm <ninjatools [at] hush.com>
#      Version: $Revision$
#  Description: Parent class for External Payloads, inherits from Payload.
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Msf::ExternalPayload;
use strict;
use base 'Msf::Payload';

sub new {
  my $class = shift;
  my $hash = @_ ? shift : { };
  my $self = $class->SUPER::new($hash);
  return($self);
}

sub Build {
  my $self = shift;
  my $opts = { };
  foreach (keys(%{$self->UserOpts})) {
    $opts->{$_} = $self->GetVar($_);
  }
  return($self->Generate($opts));
}

sub Generate {
  my $self = shift;
  my $opts = shift;
  my $prog = $self->{'Filename'};
  my $args;
  
  foreach (keys(%{$opts})) {
    $args .= $_ . '=' . $opts->{$_} . ' ';
  }
  
  if(! -e $prog)  {
    $self->SetError("Program $prog does not exist");
    return;
  }

  $self->PrintDebugLine(3, "Running: $prog $args");
  local $/;
  open(PROG, "$prog $args 2>/dev/null |") ||
  do 
  {
    $self->SetError("Couldn't open $prog: $!");
    return;
  };
  
  my $data = <PROG>;
  close(PROG);
  return($data);
}

1;
