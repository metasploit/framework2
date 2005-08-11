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
	'MGMT'      => 'afa8bd80-7d8a-11c9-bef4-08002b102989',  # v2.0
	'REMACT'    => '4d9f4ab8-7d1c-11cf-861e-0020af6e7c57',  # v0.0
	'SYSACT'    => '000001a0-0000-0000-c000-000000000046',  # v0.0
	'LSA_DS'    => '3919286a-b10c-11d0-9ba8-00c04fd92ef5',  # v0.0
	'SAMR'      => '12345778-1234-abcd-ef00-0123456789ac',  # v1.0
	'MSMQ'      => 'fdb3a030-065f-11d1-bb9b-00a024ea5525',  # v1.0
	'EVENTLOG'  => '82273fdc-e32a-18c3-3f78-827929dc23ea',  # v0.0
	'SVCCTL'    => '367abb81-9844-35f1-ad32-98f038001003',  # v2.0
);

sub UUID { return UUID_to_Bin($UUIDS{shift()}) }

sub UUID_to_Bin {
	my $uuid = shift || return;
	my @chunks = split(/\-/, $uuid);
    return
		pack('V', hex($chunks[0])).
		pack('v', hex($chunks[1])).
		pack('v', hex($chunks[2])).
		pack('n', hex($chunks[3])).
		pack('H*',$chunks[4]
	);
}

sub Bin_to_UUID {
	my $data = shift || return;
	return sprintf("%.8x-%.4x-%.4x-%.4x-%s",
		unpack('V', substr($data, 0, 4)),
		unpack('v', substr($data, 4, 2)),
		unpack('v', substr($data, 6, 2)),
		unpack('n', substr($data, 8, 2)),
		unpack('H*',substr($data,10, 6))
	);
}

sub UUID_Random {
	my $uuid;
	for (1 .. 16) { $uuid .= chr(rand()*255); }
	return $uuid;
}

sub TransferSyntax {
	return UUID_to_Bin('8a885d04-1ceb-11c9-9fe8-08002b104860')
}

sub TransferSyntaxVersion {
	return '2.0';
}

sub Request {
    my $opnum = @_ ? shift : 0;
    my $data  = @_ ? shift : '';
	my $size  = @_ ? shift : length($data);
	my $ctx   = @_ ? shift : 0;
	
    my $dlen  = length($data);
    my @res;

    my @frags;
    while (length($data)) {
        my $chunk = substr($data, 0, $size);
        $data = substr($data, $size);
        push @frags, $chunk;
    }

    # Flags: 1=First 2=Last 3=Both  
    if (scalar(@frags) == 0) {
        return (RequestBuild(3, $opnum, '', $ctx));
    }
       
    if (scalar(@frags) == 1) {
        return (RequestBuild(3, $opnum, $frags[0], $ctx));
    }

    my $first = shift(@frags);
    push @res, RequestBuild(1, $opnum, $first, $ctx);

    while (scalar(@frags) != 1) {
        my $next = shift(@frags);
        push @res, RequestBuild(0, $opnum, $next, $ctx);
    }
    
    my $last = shift(@frags);
    push @res, RequestBuild(2, $opnum, $last, $ctx);
    return(@res);
}

sub RequestBuild {
    my $flags = @_ ? shift : 3;
    my $opnum = @_ ? shift : 0;
    my $data  = @_ ? shift : '';
	my $ctx   = @_ ? shift : 0;

    my $dlen = length($data);
    my $flen = $dlen + 24;

    return pack('CCCCNvvVVvv',
        5,      # major version 5
        0,      # minor version 0
        0,      # request type
        $flags, # flags
        0x10000000,		# data representation
        $dlen+24, 		# frag length
        0,      # auth length
        0,      # call id
        $dlen,  # alloc hint
        $ctx,   # context id
        $opnum, # opnum
        ). $data;
}


sub Bind {
	my $uuid = @_ ? shift : return;
	my $iver = @_ ? shift : return;
	my $tsyn = TransferSyntax();
	my $sver = TransferSyntaxVersion();

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

##
# Windows 2000 / NT 4.0 can accept hundreds of contexts in a single requests
# Windows 2003 will only accept about 20 contexts before it starts to error
##
sub BindFakeMulti {
	my $uuid = @_ ? shift : return;
	my $iver = @_ ? shift : return;
	my $bind_head = @_ ? shift : int((rand()*6) + 10);
	my $bind_tail = @_ ? shift : int((rand()*3) + 1);
	my $tsyn = TransferSyntax();
	my $sver = TransferSyntaxVersion();

	my ($imaj, $imin) = split(/\./, $iver);
	$imin = defined($imin) ? $imin : 0;

	my $bind_total = $bind_head + $bind_tail + 1;
	
	my ($real_ctx, $ctx) = (0, 0);

	my $head  = pack('CCCCNvvVvvVV',
		5,      # major version 5
		0,      # minor version 0
		11,     # bind type
		3,      # flags
		0x10000000,     # data representation
		0,      # frag length (fixed up later)
		0,      # auth length
		0,      # call id
		5840,   # max xmit frag
		5840,   # max recv frag
		0,      # assoc group
		$bind_total,    # num ctx items
	);
	
	my $data = $head;
	
	foreach (1 .. $bind_head) {
		my $rand_uuid = UUID_Random();
		my $rand_imaj = int(rand()*6)+1;
		my $rand_imin = int(rand()*4);		
		$data .= pack('vvA16vvA16V',
			$ctx++,      # context id
			1,           # num trans items		
			$rand_uuid,  # interface uuid
			$rand_imaj,  # interface major version
			$rand_imin,  # interface minor version
			$tsyn,       # transfer syntax
			$sver,       # syntax version		
		);
	}
	
	$real_ctx = $ctx;
	
	$data .= pack('vvA16vvA16V',
		$ctx++, # context id
		1,      # num trans items		
		$uuid,  # interface uuid
		$imaj,  # interface major version
		$imin,  # interface minor version
		$tsyn,  # transfer syntax
		$sver,  # syntax version		
	);

	foreach (1 .. $bind_tail) {
		my $rand_uuid = UUID_Random();
		my $rand_imaj = int(rand()*6)+1;
		my $rand_imin = int(rand()*4);	
		$data .= pack('vvA16vvA16V',
			$ctx++,      # context id
			1,           # num trans items			
			$rand_uuid,  # interface uuid
			$rand_imaj,  # interface major version
			$rand_imin,  # interface minor version
			$tsyn,       # transfer syntax
			$sver,       # syntax version		
		);
	}
	
	# Patch up the fragment length size
	substr($data, 8, 2, pack('v', length($data))); 

	return ($data, $real_ctx);
}


sub AlterContext {
	my $uuid = @_ ? shift : return;
	my $iver = @_ ? shift : return;
	my $tsyn = TransferSyntax;
	my $sver = TransferSyntaxVersion;

	my ($imaj, $imin) = split(/\./, $iver);
	$imin = defined($imin) ? $imin : 0;

	return pack('CCCCNvvVvvVVvvA16vvA16V',
		5,      # major version 5
		0,      # minor version 0
		14,     # alter context
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

sub ReadResponse {
	my $sock = shift;
	my $head = $sock->Recv(10, 10);
	
	# Check the DCERPC header
	return if (! $head || length($head) < 10);
	
	# Read the DCERPC body
	my $dlen = unpack('v', substr($head, 8, 2));
	my $body = $sock->Recv($dlen - 10, 10);
	my $resp = DecodeResponse($head.$body);
	
	return $resp;
}

sub DecodeResponse {
	my $raw  = shift || return {};
	my $res = {};

	return if length($raw) < 24;

	my $type = unpack('C', substr($raw, 2, 1));

	$res->{'Raw'} = $raw;

	# process a bind_ack message
	if ($type == 12 || $type == 15)
	{
		$res->{'Type'} = ($type == 12) ? 'bind_ack' : 'alter_context_resp';
		(   
			$res->{'MajorVersion'},
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
		
		# XXX this gets weird/broken with 4 digit port number addresses
		$raw = substr($raw, 26 + $res->{'SecAddrLen'});

		(   
			undef, undef,
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
		(   
			$res->{'MajorVersion'},
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
		(   
			$res->{'MajorVersion'},
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


# Quick function to list interfaces via the endpoint mapper
sub MGMT_INQ_IF_IDS {
    my $sock = shift;
    my ($res, $rpc, %ints);
    
    $sock->Send(Bind(UUID('MGMT'), '1.0'));
    $rpc = ReadResponse($sock);
    
    if ($rpc->{'AckResult'} != 0) {
        print "Bind Error: " .$rpc->{'AckReason'}."\n";
        return;
    }

    my @pkts = Request(0);
    foreach my $t (@pkts) {
        my $ret = $sock->Send($t);
    }

    $rpc = ReadResponse($sock);
    
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

1;
