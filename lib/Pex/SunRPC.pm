
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

sub Clnt_create {
	my ($arg, $host, $port, $prog, $vers, $proto_req) = @_;

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

	$sock = Msf::Socket::Udp->new
	(
		'PeerAddr'   => $host,
		'PeerPort'   => $port,
	);
	if($sock->IsError)
	{
		return -1;
	}

	my $request =
		Pex::XDR::UInt(rand(0xffffffff)).	# XID
		Pex::XDR::UInt(CALL).			# CALL
		Pex::XDR::UInt(2).			# RPC Version
		Pex::XDR::UInt(PMAP_PROG).		# Program Number
		Pex::XDR::UInt(PMAP_VERS).		# Program Version
		Pex::XDR::UInt(PMAPPROC_GETPORT).	# Program Procedure 
		Pex::XDR::Enum(AUTH_NULL).		# Authentication Flavor
		Pex::XDR::VOpaque(undef, 400).		# Authentication Body	
		Pex::XDR::Enum(AUTH_NULL).		# Verification Flavor
		Pex::XDR::VOpaque(undef, 400).		# Verification Body	
		Pex::XDR::UInt($prog).			# Requested Program 
		Pex::XDR::UInt($vers).			# Requested Program Version 
		Pex::XDR::UInt($req).			# Requested Protocol
		Pex::XDR::VOpaque(undef);		# Supplemental Arguments.

	$sock->Send($request);
	my $reply = $sock->Recv(-1, 5);
	$sock->Close();

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

sub Authnull_create {
	my $arg = shift;

	%$arg->{'auth_type'} = AUTH_NULL;
	%$arg->{'auth_data'} = "";

	return 0;
}

sub Authunix_create {
	my ($arg, $hostname, $uid, $gid, $gids) = @_;

	%$arg->{'auth_type'} = AUTH_UNIX;
	%$arg->{'auth_data'} =
		Pex::XDR::UInt(time() + 20001).		# stamp
		Pex::XDR::String($hostname, 255).	# hostname
		Pex::XDR::UInt($uid).			# Remote UID
		Pex::XDR::UInt($gid).			# Remote GID
# XXX:		Pex::XDR::VArray($gids, \&Pex::XDR::UInt, 10).
		pack("N", 0);				# XXX: Fix this.

	return 0;
}

sub Clnt_call {
	my ($arg, $procedure, $data) = @_;

	my $sock = %$arg->{'sock'};

	if($sock == -1)
	{
		if(%$arg->{'protocol'} eq "tcp")
		{
			$sock = Msf::Socket::Tcp->new
			(
				'PeerAddr'   => %$arg->{'rhost'},
				'PeerPort'   => %$arg->{'rport'},
			);
		}
		elsif(%$arg->{'protocol'} eq "udp")
		{
			$sock = Msf::Socket::Udp->new
			(
				'PeerAddr'   => %$arg->{'rhost'},
				'PeerPort'   => %$arg->{'rport'},
			);
		}
		else
		{
			return -1;
		}

		if($sock->IsError)
		{
			return -1;
		}

		%$arg->{'sock'} = $sock;
	}

	my $request =
		Pex::XDR::UInt(rand(0xffffffff)).	# XID
		Pex::XDR::UInt(CALL).			# CALL
		Pex::XDR::UInt(2).			# RPC Version
		Pex::XDR::UInt(%$arg->{'rpc_prog'}).	# Program 
		Pex::XDR::UInt(%$arg->{'rpc_vers'}).	# Program Version 
		Pex::XDR::UInt($procedure).		# Program Procedure 
		Pex::XDR::Enum(%$arg->{'auth_type'}).	# Authentication Flavor
		Pex::XDR::VOpaque(%$arg->{'auth_data'}, 400).	# Authentication Body	
		Pex::XDR::Enum(AUTH_NULL).		# Verification Flavor
		Pex::XDR::VOpaque("", 400).		# Verification Body	
		$data;					# Procedure Arguments.

	$sock->Send(Pex::XDR::UInt(0x80000000 | length($request)) . $request);
	my $reply = $sock->Recv(-1, 5);

	if(length($reply) < 24 ||
		unpack("N", substr($reply, 12, 4)) != MSG_ACCEPTED ||
		unpack("N", substr($reply, 20, 4)) != SUCCESS)
	{
		return -1;
	}

	%$arg->{'data'} = "";
	if(length($reply) >= 24)
	{
		%$arg->{'data'} = substr($reply, 24);
	}

	return 0;
}

sub Clnt_destroy {
	my ($arg) = @_;

	if(%$arg->{'sock'} != -1)
	{
		%$arg->{'sock'}->Close();
	}

	foreach(keys %{$arg})
	{
		delete(%$arg->{$_});
	}
}

1;
