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

# This module is light years from being complete, however it
# is capable of some simple tasks (dumping MGMT interfaces).

my %UUIDS =
(
    'MGMT'      => 'afa8bd80-7d8a-11c9-bef4-08002b102989',  # v2.0
    'REMACT'    => '4d9f4ab8-7d1c-11cf-861e-0020af6e7c57',  # v0.0
    'SYSACT'    => '000001a0-0000-0000-c000-000000000046',  # v0.0
    'LSA_DS'    => '3919286a-b10c-11d0-9ba8-00c04fd92ef5',  # v0.0
);

sub UUID { return UUID_to_Bin($UUIDS{shift()}) }
sub DCEXFERSYNTAX { return UUID_to_Bin('8a885d04-1ceb-11c9-9fe8-08002b104860') } # v2.0

sub UUID_to_Bin {
    my $uuid = shift || return;
    my @chunks = split(/\-/, $uuid);
    return 
        pack('V', hex($chunks[0])).
        pack('v', hex($chunks[1])).
        pack('v', hex($chunks[2])).
        pack('n', hex($chunks[3])).
        pack('H*',$chunks[4]);
}

sub Bin_to_UUID {
    my $data = shift || return;
    return sprintf("%.8x-%.4x-%.4x-%.4x-%s",
        unpack('V', substr($data, 0, 4)),
        unpack('v', substr($data, 4, 2)),
        unpack('v', substr($data, 6, 2)),
        unpack('n', substr($data, 8, 2)),
        unpack('H*',substr($data,10, 6)));
}

sub Bind {
    my $uuid = @_ ? shift : return;
    my $iver = @_ ? shift : return;
    my $tsyn = @_ ? shift : DCEXFERSYNTAX();
    my $sver = @_ ? shift : '2.0';

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
    my $opnum = @_ ? shift : 0;
    my $data  = @_ ? shift : '';
    my $dlen  = length($data);
    my $size = @_ ? shift : $dlen;
    my @res;


    my @frags;
    while (length($data)) {
        my $chunk = substr($data, 0, ($size-24));
        $data = substr($data, ($size-24));
        push @frags, $chunk;
    }
    
    # Flags: 1=First 2=Last 3=Both
    
    if (scalar(@frags) == 0) {
        return (RequestBuild(3, 0, $opnum));
    }
       
    if (scalar(@frags) == 1) {
        return (RequestBuild(3, $dlen, $opnum, $frags[0]));
    }

    my $first = shift(@frags);
    push @res, RequestBuild(1, $dlen, $opnum, $first);

    while (scalar(@frags) != 1) {
        my $next = shift(@frags);
        push @res, RequestBuild(0, $dlen, $opnum, $next);
    }
    
    my $last = shift(@frags);
    push @res, RequestBuild(2, $dlen, $opnum, $last);
    return(@res);
}

sub RequestBuild {
    my $flags = @_ ? shift : 3;
    my $dlen  = @_ ? shift : 0;
    my $opnum = @_ ? shift : 0;
    my $data  = @_ ? shift : '';
    
    my $flen = length($data);
    
    return pack('CCCCNvvVVvv', 
        5,      # major version 5
        0,      # minor version 0
        0,      # request type
        $flags, # flags
        0x10000000,     # data representation
        $flen,  # frag length
        0,      # auth length
        0,      # call id
        $dlen+24,  # alloc hint
        0,      # context id
        $opnum, # opnum
        ). $data;
}


sub MGMT_INQ_IF_IDS {
    my ($host, $port) = @_;
    my ($res, $rpc, %ints);

    my $s = Pex::Socket->new();
    return if ! $s->Tcp($host, $port);

    $s->Send(Bind(UUID('MGMT'), '1.0', DCEXFERSYNTAX(), '2'));
    $res = $s->Recv(60, 10);
    $rpc = DecodeResponse($res);
    
    if ($rpc->{'AckResult'} != 0) {
        print "Bind Error: " .$rpc->{'AckReason'}."\n";
        return;
    }

    my @pkts = Request(0);
    foreach my $t (@pkts) {
        my $ret = $s->Send($t);
    }

    $res = $s->Recv(-1, 10);
    $rpc = DecodeResponse($res);
    
    if ($rpc->{'Type'} eq 'fault') {
        printf ("Call Error: 0x%.8x\n", $rpc->{'Status'});
        return;
    }
    
    # very ugly inq_if_ids() response parsing :( 
    my $status  = unpack('N', $rpc->{'StubData'});
    my $ifcount = unpack('V', substr($rpc->{'StubData'}, 4, 4));
    my $ifstats = substr($rpc->{'StubData'}, 12, 4 * $ifcount);
    my $iflist  = substr($rpc->{'StubData'}, 12 + (4 * $ifcount));
    
    while (length($iflist) >= 20) {   
        my $if = Bin_to_UUID($iflist);
        $ints{$if}=unpack('v',substr($iflist, 16)).".".unpack('v',substr($iflist, 18));
        $iflist = substr($iflist, 20);
    }
    return %ints;
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

1;
