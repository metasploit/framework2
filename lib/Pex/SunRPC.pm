
###############

##
#         Name: SunRPC.pm
#       Author: vlad902 <vlad902 [at] gmail.com>
#      Version: $Revision$
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Pex::SunRPC;
use strict;

use Pex::XDR;

use constant PMAP_PROG		=> 100000;
use constant PMAP_VERS		=> 2;
use constant PMAPPROC_GETPORT	=> 3;

use constant AUTH_NULL		=> 0;
use constant AUTH_UNIX		=> 1;

use constant CALL		=> 0;
use constant REPLY		=> 1;

use constant MSG_ACCEPTED	=> 0;

use constant SUCCESS		=> 0;


# XXX: Support in coming frags
sub Clnt_create {
	my ($arg, $host, $port, $prog, $vers, $proto_init, $proto_req) = @_;

	my $req;
	if($proto_req eq "udp")
	{
		$req = 17;
	}
	elsif($proto_req eq "tcp")
	{
		$req = 6;
	}
	else
	{
		return -1;
	}

	my $sock;
	if(($sock = MakeSock($proto_init, $host, $port)) == -1)
	{
		return -1;
	}

	my $request =
		Pex::XDR::Encode_int(rand(0xffffffff)).		# XID
		Pex::XDR::Encode_int(CALL).			# CALL
		Pex::XDR::Encode_int(2).			# RPC Version
		Pex::XDR::Encode_int(PMAP_PROG).		# Program Number
		Pex::XDR::Encode_int(PMAP_VERS).		# Program Version
		Pex::XDR::Encode_int(PMAPPROC_GETPORT).		# Program Procedure 
		Pex::XDR::Encode_int(AUTH_NULL).		# Authentication Flavor
		Pex::XDR::Encode_vopaque(undef, 400).		# Authentication Body	
		Pex::XDR::Encode_int(AUTH_NULL).		# Verification Flavor
		Pex::XDR::Encode_vopaque(undef, 400).		# Verification Body	
		Pex::XDR::Encode_int($prog).			# Requested Program 
		Pex::XDR::Encode_int($vers).			# Requested Program Version 
		Pex::XDR::Encode_int($req).			# Requested Protocol
		Pex::XDR::Encode_vopaque(undef);		# Supplemental Arguments.

# XXX: Error checking?
	SendData($sock, $proto_init, $request, $arg);
	my $reply = RecvData($sock, $proto_init);
	CloseSock($sock);

	if(length($reply) < 20 ||
		unpack("N", substr($reply, 8, 4)) != MSG_ACCEPTED ||
		unpack("N", substr($reply, 16, 4)) != SUCCESS)
	{
		return -1;
	}

	my %retval;
	$retval{'sock'} = -1;
	$retval{'rhost'} = $host;
	$retval{'rport'} = unpack("N", substr($reply, 24, 4));
	$retval{'auth_type'} = AUTH_NULL;
	$retval{'auth_data'} = "";
	$retval{'protocol'} = $proto_req;
	$retval{'rpc_prog'} = $prog;
	$retval{'rpc_vers'} = $vers;

	if($retval{'rport'} == 0)
	{
		return -1;
	}

	%{$arg} = %retval;

	return 0;
}

sub Clnt_call {
	my ($arg, $procedure, $data) = @_;

	my $sock = $arg->{'sock'};
	if($sock == -1)
	{
		if(($arg->{'sock'} = $sock = MakeSock($arg->{'protocol'}, $arg->{'rhost'}, $arg->{'rport'})) == -1)
		{
			return -1;
		}
	}

	my $request =
		Pex::XDR::Encode_int(rand(0xffffffff)).		# XID
		Pex::XDR::Encode_int(CALL).			# CALL
		Pex::XDR::Encode_int(2).			# RPC Version
		Pex::XDR::Encode_int($arg->{'rpc_prog'}).	# Program 
		Pex::XDR::Encode_int($arg->{'rpc_vers'}).	# Program Version 
		Pex::XDR::Encode_int($procedure).		# Program Procedure 
		Pex::XDR::Encode_int($arg->{'auth_type'}).	# Authentication Flavor
		Pex::XDR::Encode_vopaque($arg->{'auth_data'}, 400).	# Authentication Body	
		Pex::XDR::Encode_int(AUTH_NULL).		# Verification Flavor
		Pex::XDR::Encode_vopaque(undef, 400).		# Verification Body	
		$data;						# Procedure Arguments.

# XXX: Error checking?
	SendData($sock, $arg->{'protocol'}, $request, $arg);
	my $reply = RecvData($sock, $arg->{'protocol'});

	if(length($reply) < 20 ||
		unpack("N", substr($reply, 8, 4)) != MSG_ACCEPTED ||
		unpack("N", substr($reply, 16, 4)) != SUCCESS)
	{
		return -1;
	}

	$arg->{'data'} = "";
	if(length($reply) >= 24)
	{
		$arg->{'data'} = substr($reply, 24);
	}

	return 0;
}

sub Clnt_destroy {
	my ($arg) = @_;

	if($arg->{'sock'} != -1)
	{
		CloseSock($arg->{'sock'});
	}

	foreach(keys %{$arg})
	{
		delete($arg->{$_});
	}
}

sub Authnull_create {
	my $arg = shift;

	$arg->{'auth_type'} = AUTH_NULL;
	$arg->{'auth_data'} = "";

	return 0;
}

sub Authunix_create {
	my ($arg, $hostname, $uid, $gid, $gids) = @_;

	$arg->{'auth_type'} = AUTH_UNIX;
	$arg->{'auth_data'} =
		Pex::XDR::Encode_int(time() + 20001).		# stamp
		Pex::XDR::Encode_string($hostname, 255).	# hostname
		Pex::XDR::Encode_int($uid).			# Remote UID
		Pex::XDR::Encode_int($gid).			# Remote GID
# XXX:		Pex::XDR::Encode_varray($gids, \&Pex::XDR::Encode_int, 10).
		pack("N", 0);				# XXX: Fix this.

	return 0;
}



sub MakeSock {
	my ($proto_init, $h, $p, $args) = @_;

	my %sock_args = (
		'PeerAddr' => $h,
		'PeerPort' => $p,
	);

	my $sock;
	if($proto_init eq "tcp")
	{
		$sock = Msf::Socket::Tcp->new
		(
			%sock_args
		);
	}
	elsif($proto_init eq "udp")
	{
		$sock = Msf::Socket::Udp->new
		(
			%sock_args
		);
	}
	else
	{
# XXX: A little warning would be nice.
		return -1;
	}

	if($sock->IsError)
	{
# XXX: A little warning would be nice.
		return -1;
	}

	return $sock;
}

sub SendData {
	my ($sock, $proto, $data, $arg) = @_;

	if($proto eq "udp")
	{
		$sock->Send($data);
	} 
	elsif($proto eq "tcp")
	{
# Assumes length($data) <= 0x7fffffff
		$data =
			Pex::XDR::Encode_int(0x80000000 | length($data)).
			$data;
		$sock->Send($data);
	}
	else
	{
# XXX: A little warning would be nice.
		return -1;
	}
}

sub RecvData {
	my ($sock, $proto) = @_;

	my $data = $sock->Recv(-1, 5);

	if($proto eq "tcp" && length($data) >= 4)
	{
		$data = substr($data, 4);
	}

	return $data; 
}

sub CloseSock {
	my ($sock) = @_;

	$sock->Close();
}



# XXX: REDO THIS! Parse incoming data.
sub Portmap_request {
	my ($host, $port, $vers, $proc, $data) = @_;

	my $sock;
	if(($sock = MakeSock("udp", $host, $port)) == -1)
	{
		return -1;
	}

	my $request =
		Pex::XDR::Encode_int(rand(0xffffffff)).		# XID
		Pex::XDR::Encode_int(CALL).			# CALL
		Pex::XDR::Encode_int(2).			# RPC Version
		Pex::XDR::Encode_int(PMAP_PROG).		# Program Number
		Pex::XDR::Encode_int($vers).			# Program Version
		Pex::XDR::Encode_int($proc).			# Program Procedure 
		Pex::XDR::Encode_int(AUTH_NULL).		# Authentication Flavor
		Pex::XDR::Encode_vopaque(undef, 400).		# Authentication Body	
		Pex::XDR::Encode_int(AUTH_NULL).		# Verification Flavor
		Pex::XDR::Encode_vopaque(undef, 400).		# Verification Body	
		$data;

	my %empty;
	SendData($sock, "udp", $request, \%empty);
	my $reply = RecvData($sock, "udp");
	CloseSock($sock);

	return $reply;
}





# 395658
# sgi_printer?!

sub Program2Name {
	my $request = shift;

	open RPCN, "data/rpc_names" || die "open failed";

	while(<RPCN>)
	{
		if(!$_ || $_ =~ /^#/)
		{
			next;
		}

		if($_ =~ /^(.+?)(\s+)(\d+)(.*)$/)
		{
			if($request == $3)
			{
				return $1;
			}
		}
	}

	return "UNKNOWN-$request";
}

1;
