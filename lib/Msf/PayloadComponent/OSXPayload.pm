#!/usr/bin/perl
###############

##
#         Name: OSXPayload.pm
#       Author: H D Moore <hdm [at] metasploit.com>
#      Version: $Revision$
#  Description: Parent class for OS X (ppc) payloads.
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Msf::PayloadComponent::OSXPayload;
use strict;
use base 'Msf::Payload';
use Pex::Utils;
use vars qw{@ISA};

sub _Import {
  my $class = shift;
  @ISA = ('Msf::Payload');
  foreach (@_) {
    eval("use $_");
    unshift(@ISA, $_);
  }
}

sub new {
    my $class = shift;
    my $hash = @_ ? shift : { };
    my $self = $class->SUPER::new($hash);
    $self->InitOSX;
    return($self);
}

sub InitOSX {
    my $self = shift;
}

sub OSXPayload {
  my $self = shift;
  return($self->_Info->{'OSXPayload'});
}

sub Size {
    my $self = shift;
    my $size = length($self->Build);
    $self->PrintDebugLine(3, "OSXPayload: returning Size of $size");
    return $size;
}

sub Build {
  my $self = shift;
  return($self->BuildOSX($self->OSXPayload));
}

sub BuildOSX {
    my $self = shift;
    my $osxHash = shift;
    my $payload  = $osxHash->{'Payload'};
    my $generated = $payload;    

    my $opts = $osxHash->{'Offsets'};
    
    foreach my $opt (keys(%{ $opts })) {
        
        my ($offset, $opack) = @{ $osxHash->{'Offsets'}->{$opt} };
        my $type = $opts->{$opt}->[1];    
        
        $self->PrintDebugLine(3, "OSXPayload: opt=$opt type=$type");   
        if (my $val = $self->GetVar($opt)) {
            $self->PrintDebugLine(3, "OSXPayload: opt=$opt type=$type val=$val");      
            $val = ($type eq 'ADDR') ? gethostbyname($val) : pack($opack, $val);
            substr($generated, $offset, length($val), $val); 
        }
    }
   
    return $generated;
}

1;
