#!/usr/bin/perl
###############

##
#         Name: Win32Payload.pm
#       Author: H D Moore <hdm [at] metasploit.com>
#      Version: $Revision$
#  Description: Parent class for win32 payloads, supports multiple process
#               exit methods, etc. Inherits from Payload.
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Msf::PayloadComponent::Win32Payload;
use strict;
use base 'Msf::Payload';
use Pex::Utils;
use vars qw{@ISA};

sub import {
  my $class = shift;
  @ISA = ('Msf::Payload');
  foreach (@_) {
    eval("use $_");
    unshift(@ISA, $_);
  }
}


my $exit_types = 
{ 
    "process" => Pex::Utils::RorHash("ExitProcess"),
    "thread"  => Pex::Utils::RorHash("ExitThread"),
    "seh"     => Pex::Utils::RorHash("SetUnhandledExceptionFilter"),
};

sub new {
    my $class = shift;
    my $hash = @_ ? shift : { };
    my $self = $class->SUPER::new($hash);
    $self->InitWin32;
    return($self);
}

sub InitWin32 {
    my $self = shift;
    $self->{'Win32Payload'} = $self->{'Info'}->{'Win32Payload'};
    $self->{'Info'}->{'UserOpts'}->{'EXITFUNC'} = [0, 'DATA', 'Exit technique: "process", "thread", "seh"', 'seh'];
}

sub Size {
    my $self = shift;
    my $size = 0;
    $size += length($self->{'Win32Payload'}->{'Payload'});
    $size++; # take into account the prepended clear direction instruction
    $self->PrintDebugLine(3, "Win32Payload: returning Size of $size");
    return $size;
}

sub Build {
    my $self = shift;
    my $payload  = $self->{'Win32Payload'}->{'Payload'};

    my $exit_offset = $self->{'Win32Payload'}->{'Offsets'}->{'EXITFUNC'}->[0];
    my $generated = $payload;    

    my $opts = $self->{'Win32Payload'}->{'Offsets'};
    
    foreach my $opt (keys(%{ $opts })) {
        next if $opt eq 'EXITFUNC';
        
        my ($offset, $opack) = @{ $self->{'Win32Payload'}->{'Offsets'}->{$opt} };
        my $type = $opts->{$opt}->[1];    
        
        $self->PrintDebugLine(3, "Win32Payload: opt=$opt type=$type");   
        if (my $val = $self->GetVar($opt)) {
            $self->PrintDebugLine(3, "Win32Payload: opt=$opt type=$type val=$val");      
            $val = ($type eq 'ADDR') ? gethostbyname($val) : pack($opack, $val);
            substr($generated, $offset, length($val), $val); 
        }
    }

    if($exit_offset > 0) {
        my $exit_func = ($self->GetVar('EXITFUNC')) ? $self->GetVar('EXITFUNC') : 'seh';
        my $exit_hash = exists($exit_types->{$exit_func}) ? $exit_types->{$exit_func} : $exit_types->{'seh'};
        substr($generated, $exit_offset, 4, pack('V', $exit_hash));
        $self->PrintDebugLine(3, "Win32Payload: exitfunc: $exit_offset -> $exit_hash ($exit_func)");
    }

    # temporary hack to ensure that direction bit is not set
    $generated = "\xfc".$generated;
    return $generated;
}

1;
