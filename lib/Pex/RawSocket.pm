##
#         Name: Pex::RawSocket
#       Author: H D Moore <hdm [at] metasploit.com>
#    Copyright: H D Moore / METASPLOIT.COM
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

# Successfully tested on:
#
# + Linux x86 (2.4, 2.6)
# + Cygwin (1.5.x)
# + Mac OS X (10.3.3)
#

package Pex::RawSocket;
use Socket;
use strict;

my $PROTO_IP   = defined(_IPPROTO_IP())  ? _IPPROTO_IP()  : 0;
my $PROTO_RAW  = defined(_IPPROTO_RAW()) ? _IPPROTO_RAW() : 255;
my $OPT_IPHDR  = defined(_IP_HDRINCL())  ? _IP_HDRINCL()  : 2;

sub new {
    my $cls = shift;
    socket(my $s, PF_INET, SOCK_RAW, $PROTO_RAW) || return undef;
    setsockopt($s, $PROTO_IP, $OPT_IPHDR, 1) || return undef;
    
    my $obj = bless {}, $cls;
    $obj->{'SOCKET'} = $s;
    return $obj;
}

sub send {
    my $self = shift;
    my $data = shift;
    my $addr = shift;
    
    $addr = gethostbyname($addr);
    return undef if ! $addr;
    
    my $dst = sockaddr_in(0, $addr);
    return send($self->{'SOCKET'}, $data, 0, $dst);
}

sub recv      { }
sub blocking  { }
sub autoflush { }
sub shutdown  { }

sub handle {
    my $self = shift;
    return $self->{'SOCKET'};
}


sub _IPPROTO_IP {
    if (defined(&IPPROTO_IP)) {
        return IPPROTO_IP();
    }
    if (
            $^O eq 'darwin'   ||
            $^O eq 'linux'    ||
            $^O eq 'freebsd'  ||
            $^O eq 'openbsd'  ||
            $^O eq 'netbsd'   ||
            $^O eq 'aix'      ||
        0
        ) {
        return 0;
    } 
}

sub _IPPROTO_RAW {
    if (defined(&IPPROTO_RAW)) {
        return IPPROTO_RAW();
    }
    if (
            $^O eq 'darwin'   ||
            $^O eq 'linux'    ||
            $^O eq 'freebsd'  ||
            $^O eq 'openbsd'  ||
            $^O eq 'netbsd'   ||
            $^O eq 'aix'      ||
        0
        ) {
        return 255;
    } 
}

sub _IP_HDRINCL {
    if (defined(&IP_HDRINCL)) {
        return IP_HDRINCL();
    }
    if (
            $^O eq 'darwin'   ||
            $^O eq 'freebsd'  ||
            $^O eq 'openbsd'  ||
            $^O eq 'netbsd'   ||
            $^O eq 'aix'      ||
            $^O eq 'cygwin'   ||
        0
        ) {
        return 2;
    } 
    if ($^O eq 'linux') {
        return 3;
    }
    if ($^O eq 'hpux') {
        return 0x1002;
    }    
}
1;
