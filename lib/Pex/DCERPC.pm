#!/usr/bin/perl
###############

##
#         Name: DCERPC.pm
#       Author: H D Moore <hdm [at] metasploit.com>
#      Version: $Revision$
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Pex::DCERPC;
use strict;
use Pex;

my %UUIDS =
(
    'MGMT'      => "\x80\xbd\xa8\xaf\x8a\x7d\xc9\x11\xbe\xf4\x08\x00\x2b\x10\x29\x89",
    'REMACT'    => "\xb8\x4a\x9f\x4d\x1c\x7d\xcf\x11\x86\x1e\x00\x20\xaf\x6e\x7c\x57",
    'SYSACT'    => "\xa0\x01\x00\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46",
);

sub UUID { return $UUIDS{shift()} }
sub DCEXFERSYNTAX { return "\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60" }

sub Bind {
    return if scalar(@_) != 4;
    my ($uuid, $iver, $tsyn, $sver) = @_;

    my ($imaj, $imin) = split(/\./, $iver);
    $imin = defined($imin) ? $imin : 0;

    return pack('CCCCNvvVvvVVvvA16vvA16V', 
        5,      # major version 5
        0,      # minor version 0
        11,     # bind type
        3,      # flags
        0x10000000,     # data representation
        72,     # frag length
        0,      # auth length
        0,      # call id
        5840,   # max xmit frag
        5840,   # max recv frag
        0,      # assoc group
        1,      # num ctx items
        0,      # context id
        1,      # num trans items
        $uuid,  # interface uuid
        $imaj,  # interface major version
        $imin,  # interface minor version
        $tsyn,  # transfer syntax
        $sver,  # syntax version
        );
}

sub Request {
    my $opnum = shift || 0;
    my $data  = shift || '';
    my $dlen  = length($data);
    my $flen  = $dlen + 24;

    return pack('CCCCNvvVVvv', 
        5,      # major version 5
        0,      # minor version 0
        0,      # request type
        3,      # flags
        0x10000000,     # data representation
        $flen,  # frag length
        0,      # auth length
        0,      # call id
        $dlen,  # alloc hint
        0,      # context id
        $opnum, # opnum
        ). $data;
}


sub DecodeResponse {
    my $raw = shift || return {};
    my $res = {};
    
    return if length($raw) < 24;
    
    my $type = unpack('C', substr($raw, 2, 1));

    # process a bind_ack message
    if ($type == 12)
    {
        $res->{'Type'} = 'bind_ack';
        (   $res->{'MajorVersion'},
            $res->{'MinorVersion'},
            undef,
            $res->{'Flags'},
            $res->{'DataRep'},
            $res->{'FragLen'},
            $res->{'AuthLen'},
            $res->{'CallID'},
            $res->{'MaxFragXmit'},
            $res->{'MaxFragRecv'},
            $res->{'AssocGroup'},
            $res->{'SecAddrLen'},
        ) = unpack('CCCCNvvVvvVv', $raw);
        $res->{'SecAddr'} = substr($raw, 26, $res->{'SecAddrLen'});
        $raw = substr($raw, 26 + $res->{'SecAddrLen'});
        
        (   undef, undef,
            $res->{'NumResults'},
            undef, undef, undef,
            $res->{'AckResult'},
        ) = unpack('CCCCCCv', $raw);

        if ($res->{'AckResult'} != 0)
        {
            $res->{'AckReason'} = unpack('v', substr($raw, 8));
            $raw = substr($raw, 2);   
        }
        
        $raw = substr($raw, 10);
        $res->{'XferSyntax'} = substr($raw, 0, 16);
        $res->{'SyntaxVers'} = unpack('V', substr($raw, 16));
    }
    
    # process a response message
    if ($type == 2)
    {
        $res->{'Type'} = 'response';
        (   $res->{'MajorVersion'},
            $res->{'MinorVersion'},
            undef,
            $res->{'Flags'},
            $res->{'DataRep'},
            $res->{'FragLen'},
            $res->{'AuthLen'},
            $res->{'CallID'},
            $res->{'AllocHint'},
            $res->{'ContextID'},
            $res->{'CancelCnt'}
        ) = unpack('CCCCNvvVVvC', $raw);
        $res->{'StubData'} = substr($raw, length($raw)-$res->{'AllocHint'});
    }

    # process a fault message
    if ($type == 3)
    {
        $res->{'Type'} = 'fault';
        (   $res->{'MajorVersion'},
            $res->{'MinorVersion'},
            undef,
            $res->{'Flags'},
            $res->{'DataRep'},
            $res->{'FragLen'},
            $res->{'AuthLen'},
            $res->{'CallID'},
            $res->{'AllocHint'},
            $res->{'ContextID'},
            $res->{'CancelCnt'},
            undef,
            $res->{'Status'},
        ) = unpack('CCCCNvvVVvCCV', $raw);
        $res->{'StubData'} = substr($raw, length($raw)-$res->{'AllocHint'});
    }
    
    return $res;
}


sub DumpInterfaces {
    my ($host, $port) = @_;
    my ($res, $rpc);

    my $s = Pex::Socket->new();
    return if ! $s->Tcp($host, $port);

    my $bind = Bind($UUIDS{'MGMT'}, '1.0', DCEXFERSYNTAX(), '2');
    $s->Send($bind);
    $res = $s->Recv(60);
    $rpc = DecodeResponse($res);
    
    if ($rpc->{'AckResult'} != 0)
    {
        print "Bind Error: " .$rpc->{'AckReason'}."\n";
        return;
    }

    my $dump = Request(0);
    $s->Send($dump);
    $res = $s->Recv(-1);
    $rpc = DecodeResponse($res);
    
    if ($rpc->{'Type'} eq 'fault')
    {
        printf ("Call Error: 0x%.8x\n", $rpc->{'Status'});
        return;
    }
    
    my $data = $rpc->{'StubData'};
    $data = substr($data, 56);
    
    my %ints = ();
    while (length($data) >= 20) {
    
        my $if = sprintf("%.8x-%.4x-%.4x-%.4x-%s",
            unpack('V', substr($data, 0, 4)),
            unpack('v', substr($data, 4, 2)),
            unpack('v', substr($data, 6, 2)),
            unpack('n', substr($data, 8, 2)),
            unpack('H*',substr($data,10, 6))
        );
            
        $ints{$if}=unpack('v',substr($data, 16)).".".unpack('v',substr($data, 18));
        $data = substr($data, 20);
    }
    return %ints;
}


1;
