#!/usr/bin/perl
###############

##
#         Name: Win32StagedPayload.pm
#       Author: H D Moore <hdm [at] metasploit.com>
#      Version: $Revision$
#  Description: Parent class for win32 payloads, supporting staging,
#               multiple process exit methods, etc. Inherits from Payload.
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Msf::Win32StagedPayload;
use strict;
use base 'Msf::Payload';

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
    return($self);
}

sub InitWin32 {
    my $self = shift;
    $self->{'Win32StagedPayload'} = $self->{'Info'}->{'Win32StagedPayload'};
    delete($self->{'Info'}->{'Win32StagedPayload'});
    
    $self->{'Info'}->{'UserOpts'}->{'EXITFUNC'} = [0, 'DATA', 'Exit technique: "process", "thread", "seh"', 'seh'];
    $self->{'STAGE'} = 0;
}

sub Size {
    my $self = shift;
    my $stage = $self->{'Win32StagedPayload'}->[ $self->{'STAGE'} ];
    my $size = length($stage->{'Payload'});
    $self->PrintDebugLine(3, "Win32StagedPayload: returning Size of $size");
    return $size;
}

sub Build {
    my $self = shift;
    my $stage  = $self->{'Win32StagedPayload'}->[ $self->{'STAGE'} ];
    return if ! $stage;
    
    my $generated = $stage->{'Payload'};

    $self->PrintDebugLine(3, "Win32StagedPayload: generated code: " . length($generated) . " bytes\n");

    my $opts = $self->{'Info'}->{'UserOpts'};
    foreach my $opt (keys(%{ $opts }))
    {
        $self->PrintDebugLine(3, "Win32StagedPayload: opt=$opt");

        next if ! exists($stage->{'Offsets'}->{$opt});

        my ($offset, $opack) = @{ $stage->{'Offsets'}->{$opt} };
        my $type = $opts->{$opt}->[1];    
        
        $self->PrintDebugLine(3, "Win32StagedPayload: opt=$opt type=$type");   
        if (my $val = $self->GetVar($opt))
        {
            $val = ($type eq 'ADDR') ? gethostbyname($val) : pack($opack, $val);
            substr($generated, $offset, length($val), $val);
        }
    }
         
    return $generated;
}

sub NextStage {
    my $self = shift;
    $self->{'STAGE'}++;
    return $self->Build();
}



1;
