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

package Pex::RawSocket;
use Socket;
use strict;

my $PROTO_IP   = defined(&IPPROTO_IP)  ? IPPROTO_IP()  : 0;
my $PROTO_RAW  = defined(&IPPROTO_RAW) ? IPPROTO_RAW() : 255;
my $OPT_IPHDR  = defined(&IP_HDRINCL)  ? IP_HDRINCL()  : 3;

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
    
    my $dst = sockaddr_in(0, inet_aton($addr));
    return send($self->{'SOCKET'}, $data, 0, $dst);
}

sub handle {
    my $self = shift;
    return $self->{'SOCKET'};
}

1;
