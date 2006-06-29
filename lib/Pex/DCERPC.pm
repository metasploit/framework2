###############
#
#         Name: DCERPC.pm
#       Author: H D Moore <hdm [at] metasploit.com>
#       Author: Brian Caswell <bmc [at] shmoo.com>
#      Version: $Revision$
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

=head1 NAME

Pex::DCERPC - An API for implementing DCE/RPC

=cut 

package Pex::DCERPC;
use strict;
use warnings;
use Pex;
use Pex::Text;
use Pex::NDR;
use Pex::SMB;
use Pex::Socket::Tcp;
use Data::Dumper;
use vars qw/$AUTOLOAD/;

use FindBin qw{$RealBin};

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
    'SPOOLER'   => '12345678-1234-abcd-ef00-0123456789ab',
    'TAPI'      => '2F5F6520-CA46-1067-B319-00DD010662DA',
    'UMPNPMGR'  => '8d9f4e40-a03d-11ce-8f69-08003e30051b',
    'MSDTC'     => '906b0ce0-c70b-1067-b317-00dd010662da',
);

our %_protocols = map { $_, 1  } qw(ncacn_np ncacn_ip_tcp ncacn_http ncacn_ip_udp);

my %_errors;
_parse_errors("$RealBin/data/dce_errors.txt");

=head2 new

Instantiate a new instance of Pex::DCERPC.

If a handle is provided:

    Pex::DCERPC->new(handle => $handle)

Then the API automatically connects to the service via the appropriate interface provided in the handle.

Handles can be built by hand, or use "build_handle" to build one for you.

=cut 

sub new {
    my ($class, @args) = @_;
    my $self  = {};
	my $args = (@args) ? { @args } : { };
   
    bless $self, $class;

    return $self->_init($args);
}

=head2 username($arg)

=head2 password($arg)

=head2 domain($arg)

=head2 bindevasion($arg)

=head2 directsmb($arg)

Variable accessors for the above functions.

=cut

our %_variables = map {  lc($_), 1  } qw(username password domain bindevasion directsmb);
sub AUTOLOAD {
    my ($self, $value) = @_;
    my $attr = $AUTOLOAD;
    $attr =~ s/.*:://;

    if (defined($_variables{$attr})) {
        if (defined $value) {
            $self->{$attr} = $value 
        }
        return $self->{$attr};
    }
    return if $attr =~ /^[[:upper:]]+$/;
    
    # NOT US BUDDY!
    die "undefined function $attr";
}


=head2 _init

Parse new() arguments, setting up the DCE/RPC object.  If a handle was provided to new(), this function will attempt to bind to that handle.

=cut

sub _init {
    my ($self, $args) = @_;

    foreach my $variable (keys %_variables) {
        if (defined ($args->{$variable})) {
            $self->{$variable} = $args->{$variable};
        }
    }

    if ($args->{'fragsize'}) {
        $self->fragsize($args->{'fragsize'});
    } else {
        $self->fragsize(256);
    }

    if ($args->{'handle'}) {
        $self->_bind($args->{'handle'}) || return;
    }

	$self->{'error'} = '';
	
    return $self;
}

=head2 fragsize($size)

If $size is provided, sets the maximum DCE/RPC fragment size

Returns current maximum fragment size

=head3 NOTE:

Windows XP requires the maximum fragsize must be 4000 or less, therefor we ignore fragsizes that are too big or too small.
=cut

sub fragsize {
    my ($self, $size) = @_;
    if ($size && $size >= 1 && $size <= 4000) {
        $self->{'fragsize'} = $size;
    }

    return $self->{'fragsize'};
}

=head2 callid()

Returns a unique number per call per instance of the object.  This is really only used internally to bulid DCE/RPC requests that each have their own unique callid.

=cut

sub callid {
    my ($self) = @_;
    $self->{'_callid'}++;
}

=head2 UUID($UUID_NAME)

Return the binary representation of a given UUID based on name.  

=head3 NOTE:

This really shouldn't be used, since writing exploits targeting new UUIDs requires modifying this library.  Instead, the object api, providing the actual UUID in the handle.

=cut


sub UUID { return UUID_to_Bin($UUIDS{shift()}) }

=head2 UUID_to_Bin($uuid)

Convert the textual representation of a UUID (00000000-0000-0000-0000-000000000000) to the binary representation.

=cut

sub UUID_to_Bin {
    my ($self, $uuid) = self_or_default(@_);
	
    return if (!$uuid);
    return if (length($uuid) != 36);

    my @chunks = split(/\-/, $uuid);
    return
		pack('V', hex($chunks[0])).
		pack('v', hex($chunks[1])).
		pack('v', hex($chunks[2])).
		pack('n', hex($chunks[3])).
		pack('H*',$chunks[4]);
}

=head2 Bin_to_UUID($data)

Convert a binary representation of a UUID to the textual representation.

=cut

sub Bin_to_UUID {
	my $data = shift || return;
	return sprintf(
        "%.8x-%.4x-%.4x-%.4x-%s",
		unpack('V', substr($data, 0, 4)),
		unpack('v', substr($data, 4, 2)),
		unpack('v', substr($data, 6, 2)),
		unpack('n', substr($data, 8, 2)),
		unpack('H*',substr($data,10, 6))
	);
}

=head2 UUID_Random()

Return a random UUID in binary form

=cut 
sub UUID_Random {
    return Pex::Text::RandomData(16);
}

=head2 TransferSyntax()

Returns the default transfer syntax (specified as a UUID) in binary form

=cut

sub TransferSyntax {
	return UUID_to_Bin('8a885d04-1ceb-11c9-9fe8-08002b104860')
}

=head2 TransferSyntaxVersion()

Returns the default transfer syntax version

=cut

sub TransferSyntaxVersion {
	return '2.0';
}


=head2 Request($opnum, $data, $size, $context_id)

Generate the list of requests needed to perform function $opnum providing the argument $data.  The request is fragmented into maximum chunks of size $size.  The context_id is the DCE/RPC context that the operation should be done on.  The context_id should be provided by the Bind function.

Returns a list of requests that can be sent at the next layer down, be it SMB or TCP.

=cut

sub Request {
    my ($self, $opnum, $data, $size, $ctx) = self_or_default(@_);

    $opnum = 0 if !defined $opnum;
    $data = '' if !defined $data;
    $size = length($size) if !$size;
    $ctx = 0 if !$ctx;

    my @frags;
    while (length($data)) { 
        my $chunk = substr($data, 0, $size, '');
        push @frags, $chunk;
    } 

    # Flags: 1=First 2=Last 3=Both  
    if (scalar(@frags) == 0) {
        return $self->RequestBuild(3, $opnum, '', $ctx);
    }
       
    if (scalar(@frags) == 1) {
        return $self->RequestBuild(3, $opnum, $frags[0], $ctx);
    }

    my @res;
    my $first = shift(@frags);
    push (@res, $self->RequestBuild(1, $opnum, $first, $ctx));

    while (scalar(@frags) != 1) {
        my $next = shift(@frags);
        push (@res, $self->RequestBuild(0, $opnum, $next, $ctx));
    }
    
    my $last = shift(@frags);
    push (@res, $self->RequestBuild(2, $opnum, $last, $ctx));
    return(@res);
}

=head2 RequestBuild($flags, $opnum, $data, $context_id)

Build a request, only ment to be called via Request()

=cut

sub RequestBuild {
    my ($self, $flags, $opnum, $data, $ctx) = self_or_default(@_);
    
    $flags = 3 if !defined $flags;
    $opnum = 0 if !defined $opnum;
    $data = '' if !defined $data;
    $ctx = 0 if !defined $ctx;

    my $dlen = length($data);

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

=head2 Bind($UUID, $INTERFACE_VERSION)

Build a Bind request 

=cut

sub Bind {
    my ($self, $uuid, $iver) = self_or_default(@_);
  
    return if (!$uuid);
    return if (length($uuid) != 16);
    
    return if (!$iver);

	my $tsyn = TransferSyntax();
	my $sver = TransferSyntaxVersion();

	my ($imaj, $imin) = split(/\./, $iver);
	$imin = defined($imin) ? $imin : 0;

    $self->{'_bind'} = pack('CCCCNvvVvvVVvvA16vvA16V',
		5,      # major version 5
		0,      # minor version 0
		11,     # bind type
		3,      # flags
		0x10000000,      # data representation
		72,  # frag length
		0 ,       # auth length
		$self->callid(), # call id
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

    return ($self->{'_bind'}, 0);
}

##
# Windows 2000 / NT 4.0 can accept hundreds of contexts in a single requests
# Windows 2003 will only accept about 20 contexts before it starts to error
##
=head2 BindFakeMulti($UUID, $INTERFACE_VERSION)

Build a Bind request with fake UUIDs intermingled with the actual request.

Useful for IDS Evasion.

=head3 NOTE:

Enabled on object creation via:

    Pex::DCERPC->new(handle => $handle, bindevasion => 1)

=cut
sub BindFakeMulti {
    my ($self, $uuid, $iver, $bind_head, $bind_tail) = self_or_default(@_);

    return if (!$uuid);
    return if (length($uuid) != 16);
    
    return if (!$iver);

    if (!$bind_head) {
        $bind_head = int((rand()*6) + 10);
    }
    if (!$bind_tail) {
        $bind_tail = int((rand()*3) + 10);
    }

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

=head2 AlterContext($UUID, $INTERFACE_VERSION)

Build an Alter Context request, converting a handle to a new UUID.

=head3 NOTE:

Useful for IDS Evasion.

=cut
sub AlterContext {
    my ($self, $uuid, $iver) = self_or_default(@_);
    
    return if (!$uuid);
    return if (length($uuid) != 16);
    
    return if (!$iver);
	
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

=head2 ReadResponse($socket)

Read a request response from $socket, and attempt to decode it.

=cut

sub ReadResponse {
    my ($self, $sock) = self_or_default(@_);
	my $head = $sock->Recv(10, 10);
	
	# Check the DCERPC header
    if (! $head || length($head) < 10) {
        $self->{'error'} = 'not enough data for a response';
        delete $self->{'response'};
        return;
    }
	
	# Read the DCERPC body
	my $dlen = unpack('v', substr($head, 8, 2));
	my $body = $sock->Recv($dlen - 10, 10);
	my $resp = $self->DecodeResponse($head.$body);
	
	return $resp;
}

=head2 DecodeResponse($data)

Decode a given response.  The decoded response is stuffed in $self->{'response'} as well as returned.

=cut

sub DecodeResponse {
    my ($self, $raw) = self_or_default(@_);
    if (!$raw) {
        return {}
    };

    delete $self->{'response'};
	
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
        if ($res->{'AuthLen'}) {
            $res->{'AuthData'} = substr($raw, 19); # should only grab $res->{'AuthLen'}, however it doesn't seem to contain all of it...
            $res->{'auth'} = $self->ntlmssp_parse($res->{'AuthData'});
        }
	}
	elsif ($type == 2) # process a response message
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
		$res->{'StubData'} = substr($raw, 24, $res->{'FragLen'} - 24);
        #     length($raw)-$res->{'AllocHint'});
	}
    elsif ($type == 3) # process a fault message
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
        $res->{'Error'} = $self->fault2string($res->{'Status'});
	} elsif ($type eq 13) { # bind_nack
        $res->{'Type'} = 'bind_nack';
		
        (   
			$res->{'MajorVersion'},
			$res->{'MinorVersion'},
			undef,
			$res->{'Flags'},
			$res->{'DataRep'},
			$res->{'FragLen'},
			$res->{'AuthLen'},
			$res->{'CallID'},
			$res->{'Reason'},
		) = unpack('CCCCNvvVv', $raw);
		$res->{'StubData'} = substr($raw, 18);
        if ($res->{'Reason'} eq '4') {
            $res->{'Error'} = 'Protocol version not supported';
            my $count = unpack('C',substr($res->{'StubData'}, 0, 1, ''));
            for (my $i = 0; $i < $count; $i++) {
                my ($major, $minor) = unpack('CC',substr($res->{'StubData'}, 0, 2, ''));
                if (defined($major) && defined($minor)) {
                    push (@{ $res->{'Protocols'} }, "$major.$minor");
                } else {
                    last;
                }
            }
        }
    } else {
        $self->{'error'} = "unknown response type : $type";
        return;
    }

    $self->{'response'} = $res;

    return $res;
}

=head2 fault2string($fault)

Return the fault string based on a given fault ID.

=cut

sub fault2string {
    my ($self, $fault) = self_or_default(@_);
    if (!defined $_errors{$fault}) {
        return $fault;
    }

    return $_errors{$fault};
}

=head2 MGMT_INQ_IF_IDS($sock)

"Quick function to list interfaces via the endpoint mapper"

=cut
sub MGMT_INQ_IF_IDS {
    my ($self, $sock) = self_or_default(@_);
    my ($res, $rpc, %ints);
   
    my ($bind, $ctx) = Bind(UUID('MGMT'), '1.0');
    $sock->Send($bind);
    $rpc = $self->ReadResponse($sock);
    
    if ($rpc->{'AckResult'} != 0) {
        print "Bind Error: " .$rpc->{'AckReason'}."\n";
        return;
    }

    my @pkts = $self->Request(0);
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

=head2 build_handle($uuid, $version, $protocol, $address, @options)

Build a request handle, similar to Microsoft's DCE/RPC handles required to connect to a DCE/RPC service.

=cut

sub build_handle {
    my ($self, $uuid, $version, $protocol, $address, @options) = self_or_default(@_);

    return if (!UUID_to_Bin($uuid));
    return if ($version !~ /^\d+\.\d+$/);
    return if (!$_protocols{$protocol});
    return if (!$address);

    return $uuid . ':' . $version . '@' . $protocol .':' . $address . '[' . join(',', @options) .']';
}

=head2 parse_handle($handle)

Parse a request handle, ment to parse handles provided by build_handle for functions inside Pex::DCEPRC.

This function should be able to parse most handles supported by Microsoft, though with a few short comings on the list of supported protocols.  At the moment, only ncacp_np and ncanc_ip_tcp are supported.

=cut

sub parse_handle {
    my ($self, $handle) = @_;

    my $uuid_re = '[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}(?::\d+\.\d+)?';
    my $proto_re = '(?:' . join('|', keys %_protocols) . ')';

    if ($handle =~ /^($uuid_re)@($proto_re):(.*?)\[(.*)\]/) {
        my $uuid = $1;
        my $protocol = $2;
        my $host = $3;
        my $options = $4;
        my @options = split(/\s*,\s*/, $options);
        my $version = '1.0';

        if ($uuid =~ /(.*):(\d+\.\d+)/) {
            $uuid = $1;
            $version = $2;
        }
        return ($uuid, $version, $protocol, $host, @options);
    } else {
        return;
    }
}

=head2 _bind($handle)

Bind to a given DCE/RPC service.  This function is only meant to be called from inside new()

=cut 

sub _bind {
    my ($self, $handle) = self_or_default(@_);

    return if (!$handle);

    my ($uuid, $version, $protocol, $host, @options) = $self->parse_handle($handle);
    return if (!$uuid);

    my $bind = ($self->bindevasion()) ? \&BindFakeMulti : \&Bind;

    if ($protocol eq 'ncacn_np') {
        my ($pipe) = @options;
        my $target_name = '*SMBSERVER';
        my $port = ($self->directsmb()) ? 445 : 139;

        my $s = Pex::Socket::Tcp->new('PeerAddr' => $host, 'PeerPort' => $port);
        if ($s->IsError) {
			return ('SOCKET: '.$s->GetError());
        }
        
        my $x = Pex::SMB->new({ 'Socket' => $s });

        if (!$self->directsmb()) {
            $x->SMBSessionRequest($target_name);
            if ($x->Error) {
            	return ('FAILED SESSION REQUEST: '. $x->Error);
            }
        }

        $x->SMBNegotiate();
        if ($x->Error) {
            return ('FAILED NEGOTIATE: '. $x->Error);
        }
        
        $x->SMBSessionSetup(
            $self->username(),
            $self->password(),
            $self->domain(),
        );

        if ($x->Error) {
            return ('FAILED TO CREATE NULL SESSION: '. $x->Error);
        }
        
        $target_name = $x->DefaultNBName();

        my $ipc = (defined $target_name) ?  "\\\\$target_name\\IPC\$" : "\\\\\\IPC\$" ; 

        $x->SMBTConnect($ipc);
        if ($x->Error) {
			return ('FAILED TO CONNECT TO IPC: '. $x->Error);
        }


        $x->SMBCreate($pipe);
        if ($x->Error) {
            return ('FAILED TO CREATE PIPE: '. $x->Error);
        }

        my ($bind, $ctx) = &$bind($self, $self->UUID_to_Bin($uuid), $version);

        $x->SMBTransNP($x->LastFileID, $bind);
        if ($x->Error) {
            return ('BIND FAILURE: '. $x->Error);
        }
        $self->{'_handles'}{$handle}{'connection'} = $x;
        $self->{'_handles'}{$handle}{'context_id'} = $ctx;
    } elsif ($protocol eq 'ncacn_ip_tcp') {
        my ($port) = @options;
        
        my $s = Pex::Socket::Tcp->new('PeerAddr' => $host, 'PeerPort' => $port);
        if ($s->IsError) {
            return ('SOCKET: '.$s->GetError());
        }
        my ($bind, $ctx) = &$bind($self, $self->UUID_to_Bin($uuid), $version);

        my $ret = $s->Send($bind);
        if (! $ret ) {
            return ('CONNECTION CLOSED');
        }

        my $response = $self->ReadResponse($s);
        if (!$response) {
            return('NO RESPONSE TO BIND');
        }
        $self->{'_handles'}{$handle}{'connection'} = $s;
        $self->{'_handles'}{$handle}{'context_id'} = $ctx;
    } else {
		return('NO PROTOCOL SUPPORT');
    }

    1;
}

=head2 request($handle, $opnum, $data)

Perform operation $opnum on the handle $handle, providing the arguments $data.  

This function handles building, sending, and parsing the response of the given request.  Eventually, each protocol should be subclassed, but until then, this will work.

=cut 

sub request {
    my ($self, $handle, $opnum, $data) = self_or_default(@_);
  
    return if (!$handle);
    return if (!defined $opnum);

    my $connection = $self->{'_handles'}{$handle}{'connection'};
    my $context_id = $self->{'_handles'}{$handle}{'context_id'};
    
    return if (!$connection);
    return if (!defined $context_id);

    my ($uuid, $version, $protocol, $host, @options) = $self->parse_handle($handle);
    return if (!$uuid);

    my (@DCE) = $self->Request($opnum, $data, $self->fragsize(), $context_id);
    if ($protocol eq 'ncacn_np') {
        if (scalar(@DCE) > 1) {
            my $offset = 0;
            while (scalar(@DCE != 1)) {
                my $chunk = shift(@DCE);
                $connection->SMBWrite($connection->LastFileID, $offset, $chunk);
                $offset += length($chunk);
            }
        }

        my $response = $connection->SMBTransNP($connection->LastFileID, $DCE[0]);
        if ($response && $response->Get('data_bytes')) {
            $self->DecodeResponse($response->Get('data_bytes'));
            if ($self->{'response'}->{'Type'} eq 'fault') {
                return ('FAULT: ' . sprintf("0x%.8x", $self->{'response'}->{'Error'}));
            } else {
                return ('RESPONSE: ' . $self->{'response'}->{'Type'}, "STUB DATA: " .  $self->bin2hex($self->{'response'}->{'StubData'}));
            }
        } else {
			$response ||= '';
            return ('NO RESPONSE');
        }
    } elsif ($protocol eq 'ncacn_ip_tcp') {
        delete($self->{'response'});
        foreach my $DCE (@DCE) {
            my $ret = $connection->Send($DCE);
            if (! $ret ) {
				return ('CONNECTION CLOSED');
            }
        }

        # normally we would care about all of the responses, but only after the
        # last fragment does the DCE/RPC server bother responding, so we only
        # do a Recv after we have sent all of our packets.
        my $res = $connection->Recv(-1);
        $self->DecodeResponse($res);

        if (!$self->{'response'}) {
            return ('NO RESPONSE');
        }
        if ($self->{'response'}->{'Type'} eq 'fault') {
            return ('FAULT: ' . sprintf("0x%.8x",$self->{'response'}->{'Error'}));
        } 

        return ('RESPONSE: ' . $self->{'response'}->{'Type'},"STUB DATA = " .  $self->bin2hex($self->{'response'}->{'StubData'}));
    } else {
        return('NO PROTOCOL SUPPORT');
    }
}

=head2 bin2hex($data)

Convert a string into hex form, appropriate for inclusion in a perl script.

Example:

    bin2hex('AAAA')
    
Returns:

    '\x41\x41\x41\x41'

=cut

sub bin2hex {
    my ($self, $bin) = self_or_default(@_);
    return if (!$bin);
    my @data = unpack("C*", $bin);
    for (@data) {
        $_ = sprintf('\\x%2.2X', $_);
    }
    return (join ("", @data));
}

=head2 self_or_default

Ment to be called internally only... this allows all of the functions to be used as object calls as well as function calls.

=cut 

sub self_or_default {
    if (!defined($_[0]) || !UNIVERSAL::isa($_[0],'Pex::DCERPC')) {
        my $self = Pex::DCERPC->new();
        unshift(@_,$self);
    }
    return @_;
}

=head2 _parse_errors($file)

This isn't ment to be called, unless of course are mucking with Pex::DCERPC directly.

Load the error code map, only meant to be called internally.

=cut

sub _parse_errors {
    my ($file) = @_;

    open (F, '<', $file) || die;

    while (<F>) {
        next if /^#/;
        if (/^([[:xdigit:]]{8})\s+([\w_]+)/) {
            my $code = $1;
            my $string = $2;

            my $num = unpack("L",pack("H*", $code));
            $_errors{$num} = $string;
        }
    }
}

=head2 test

This isn't ment to be called, unless of course you want to test Pex::DCERPC!  Typically, this is called automagically via:

perl -Ilib lib/Pex/DCERPC.pm

=head3 NOTE:

This test function doesn't test everything.  Use t/dcerpc.pl to fully test Pex::DCERPC.

=cut

sub test {
    require Test::More;
    import Test::More;
    plan(tests => 24);
   
    is(UUID_to_Bin('6bffd098-a112-3610-9833-46c3f87e345a'), "\x98\xD0\xFF\x6B\x12\xA1\x10\x36\x98\x33\x46\xC3\xF8\x7E\x34\x5A", 'UUID_to_Bin');
    ok(!UUID_to_Bin("A" x 30), "UUID_to_Bin - invalid uuid");

    # object interface
    {
        my $dce = Pex::DCERPC->new();
        is($dce->UUID_to_Bin('6bffd098-a112-3610-9833-46c3f87e345a'), "\x98\xD0\xFF\x6B\x12\xA1\x10\x36\x98\x33\x46\xC3\xF8\x7E\x34\x5A", 'UUID_to_Bin (object wrapper)');
    }


    ok(Bind(UUID_to_Bin('6bffd098-a112-3610-9833-46c3f87e345a'), '1.0'),'bind');
    ok(!Bind(),'bind (without args)');
    ok(!Bind(UUID_to_Bin('6bffd098-a112-3610-9833-46c3f87e345a')),'bind (without interface version)');
    ok(!Bind('A','1.1'), 'bind (invalid UUID)');

    # ugly, yes... but it works for now
    {
        my $expected = "\x05\x00\x0B\x03\x10\x00\x00\x00\x48\x00\x00\x00\x00\x00\x00\x00\xD0\x16\xD0\x16\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\x34\x12\x34\x12\x34\x12\x34\x12\x12\x34\x12\x34\x12\x34\x12\x34\x01\x00\x00\x00\x04\x5D\x88\x8A\xEB\x1C\xC9\x11\x9F\xE8\x08\x00\x2B\x10\x48\x60\x02\x00\x00\x00";
        is(Bind(UUID_to_Bin('12341234-1234-1234-1234-123412341234'),'1.0'), $expected, 'bind (validating data)');
        is(Bind(UUID_to_Bin('12341234-1234-1234-1234-123412341234'),'1'), $expected, 'bind with short interface version (validating data)');
        
        my $dce = Pex::DCERPC->new();
        is($dce->Bind(UUID_to_Bin('12341234-1234-1234-1234-123412341234'), '1.0'), $expected, 'bind via object handle (validating data)'), 
    }

    {
        my $dce = Pex::DCERPC->new();
        is($dce->fault2string(5), 'nca_s_fault_access_denied', 'fault2failure 5')
    }

    # autoload
    {
        my $dce = Pex::DCERPC->new();
        $dce->username('bob');
        is($dce->username, 'bob','AUTOLOAD => username'); 
        $dce->password('bob1');
        is($dce->password, 'bob1','AUTOLOAD => password'); 
        $dce->domain('bob2');
        is($dce->domain, 'bob2','AUTOLOAD => domain'); 

        eval {
            $dce->autoload_should_fail('bob');
        };
        like($@, qr/undefined function/, 'AUTOLOAD => undefined function');
    }

    {
        my $dce = Pex::DCERPC->new();
        use Data::Dumper;


        is($dce->build_handle('6bffd098-a112-3610-9833-46c3f87e345a', '1.0', 'ncacn_ip_tcp', '10.4.10.10', 80), '6bffd098-a112-3610-9833-46c3f87e345a:1.0@ncacn_ip_tcp:10.4.10.10[80]', 'build_handle (ncacn_ip_tcp)');
        is($dce->build_handle('6bffd098-a112-3610-9833-46c3f87e345a',  '1.0','ncacn_np', '10.4.10.10', '\wkssvc'), '6bffd098-a112-3610-9833-46c3f87e345a:1.0@ncacn_np:10.4.10.10[\wkssvc]', 'build_handle (ncacn_np)');
        is($dce->build_handle('6bffd098-a112-3610-9833-46c3f87e345a',  '1.0','ncacn_ip_udp', '10.4.10.10', 1025), '6bffd098-a112-3610-9833-46c3f87e345a:1.0@ncacn_ip_udp:10.4.10.10[1025]', 'build_handle (ncacn_ip_udp)');
        is($dce->build_handle('6bffd098-a112-3610-9833-46c3f87e345a',  '1.0','ncacn_http', '10.4.10.10', 2225), '6bffd098-a112-3610-9833-46c3f87e345a:1.0@ncacn_http:10.4.10.10[2225]', 'build_handle (ncacn_http)');
        
        ok(!$dce->build_handle('6bffd098-a112-3610-9833',  '1.0','ncacn_http', '10.4.10.10', 2225), 'build_handle invalid uuid');
        ok(!$dce->build_handle('6bffd098-a112-3610-9833-46c3f87e345a', '1.0', 'ncacn_bmc', '10.4.10.10', 2225), 'build_handle invalid protocol');

        ok(
            eq_array(
                [$dce->parse_handle('6bffd098-a112-3610-9833-46c3f87e345a:1.0@ncacn_http:10.4.10.10[2225]')], 
                ['6bffd098-a112-3610-9833-46c3f87e345a', '1.0', 'ncacn_http', '10.4.10.10', '2225']
            ),
            'parse_handle'
        );
        ok(
            eq_array(
                [$dce->parse_handle('6bffd098-a112-3610-9833-46c3f87e345a@ncacn_http:10.4.10.10[2225]')], 
                ['6bffd098-a112-3610-9833-46c3f87e345a', '1.0', 'ncacn_http', '10.4.10.10', '2225']
            ),
            'parse_handle (no version)'
        );
        ok(!$dce->parse_handle('6bffd098-a112-3610-9833-46c3f87e345a@ncacn_http:10.4.10.10['), 'parse_handle invalid handle');
    }
}

if (!(caller())[0]) {
    Pex::DCERPC::test();
}

1;
