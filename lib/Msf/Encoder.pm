#!/usr/bin/perl
###############

##
#         Name: Encoder.pm
#       Author: spoonm
#      Version: $Revision$
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

my $defaults =
{
  'Name'     => 'No Name',
  'Version'  => '0.0',
  'Author'   => 'No Author',
  'Arch'     => [ ],
  'Refs'     => [ ],
  'Desc'     => 'No Description',
};

sub new {
  my $class = shift;
  my $hash = @_ ? shift : { };
  my $self = bless($hash, $class);
  $self->SetDefaults($defaults);
  $self->{'Exploit'} = shift;
  $self->{'Payload'} = shift;
  $self->{'Nop'} = shift;
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
sub _Nop {
  my $self = shift;
  $self->{'Nop'} = shift if(@_);
  return($self->{'Nop'});
}


sub Encode {
  my $self = shift;

  my $exploit = $self->_Exploit;
  my $payload = $self->_Payload;
  my $nop = $self->_Nop;

  # Os and Arch Check, if either is empty or undef, we figure it means all
#  my $iArch = $exploit->{'Info'}->{'Arch'};
#  if(defined($iArch) && @$iArch) {
#fixme not sure how to implement check.
# it would be bad to use an x86 encoder on a sparc sploit
    
  my $rawshell = $exploit->PayloadPrepend($payload) . $payload->Build . $exploit->PayloadAppend($payload);
  my $iPayload = $exploit->{'Info'}->{'Payload'};
  my $badChars = $iPayload->{'BadChars'};
  my $exploitSpace = $iPayload->{'Size'};
  my $minNops = $iPayload->{'MinNops'} || 0;
  my $maxNops = defined($iPayload->{'MaxNops'}) ? $iPayload->{'MaxNops'} : 10000000;

  my $encodedShell = $self->EncodePayload($rawshell, $badChars);

  if(!defined($encodedShell)) {
    $self->SetError("Error encoding payload"); #fixme
    return;
  }
  if(length($encodedShell) > $exploitSpace - $minNops) {
    $self->PrintDebugLine(1, "ExploitSpace: $exploitSpace");
    $self->PrintDebugLine(1, "EncodedLength: " . length($encodedShell)); 
    $self->PrintDebugLine(1, "MinNops: $minNops MaxNops: $maxNops");
    $self->SetError("Encoded payload too large for exploit");
    return;
  }

  my $emptySpace = $exploitSpace - length($encodedShell);
  my $nopSize = $maxNops < $emptySpace ? $maxNops : $emptySpace;

  my $nops = $nop->Nops($nopSize);
  if(length($nops) != $nopSize) {
    $self->SetError("Error generating nops");
    return;
  }

  foreach (split('', $badChars)) {
    if(index($nops . $encodedShell, $_) != -1) {
      $self->SetError("BadChar in encoded data");
      return;
    }
  }

  my $encodedPayload = Msf::EncodedPayload->new($rawshell, $encodedShell, $nops);
  return($encodedPayload);
}

sub EncodePayload {
  return;
}

1;
