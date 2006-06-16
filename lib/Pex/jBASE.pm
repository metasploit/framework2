
###############

##
#         Name: jBASE.pm
#       Author: H D Moore <hdm [at] metasploit.com>
#      Version: $Revision$
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Pex::jBASE;
use strict;
use Pex;


my $pseq = 0;

sub LoginAnon {
	my $sock = shift;
	return if ! $sock;
	$sock->Send
	(
		"\x0e\x47\x53\x49".pack('V', $pseq++).
		"\x1b\x00\x00\x00\x13\x08\x15\x00\x00\x00\x13\x00\x00\xff\xff\x08".
		"\x00\xf0\xaf\xe2\xc8\x6a\x7b\x18\xca\xe0\x93\x04\x00\x00\x00\x00".
		"\x00"
	);
	
	my $resp =
		"\x0e\x47\x53\x49\x00\x00\x00\x00\x0a\x00\x00\x00\x13\x08\x04\x00".
		"\x00\x00\x13\x00\x00\x00\x00\x00";

	my $data = $sock->Recv(-1, 10);
	return if $data ne $resp;
	return 1;
}

sub CMD_ReloadINI {
	my $sock = shift;
	return if ! $sock;
	$sock->Send
	(
		"\x0e\x47\x53\x49".pack('V', $pseq++).
		"\x06\x00\x00\x00\x08\x08\x00\x00\x00\x00\x08\x00"
	);
	
	my $resp =
		"\x0e\x47\x53\x49\x01\x00\x00\x00\x11\x00\x00\x00\x08\x08\x0b\x00".
		"\x00\x00\x08\x00\x00\x00\x00\x00\x05\x00\x49\x52\x50\x43\x44";		

	my $data = $sock->Recv(-1, 10);
	print "INI: $data\n";
	
	return if $data ne $resp;
	return 1;
}

sub CMD_ProbeWorkspace {
	my $sock = shift;
	my $work = shift;
	return if ! $sock;

	my $send =
		"\x0e\x47\x53\x49".pack('V', $pseq++).
		"\x0f\x00\x00\x00\x19\x08".
		pack('v', length($work)+2).
		"\x00\x00\x19\x00".
		pack('v', length($work)).
		$work;

	$sock->Send($send);
	
	my $resp =
		"\x0e\x47\x53\x49\x01\x00\x00\x00\x1a\x00\x00\x00\x19\x08\x14\x00".
		"\x00\x00\x19\x00\x00\x00\x00\x00\x3c\x00\x00\x00\x00\x00\x00\x00".
		"\x01\x00\x00\x00\x3c\x00\x00\x00";		
	
	my $data = $sock->Recv(-1, 10);
	print "WKS: $data\n";
	return if $data ne $resp;
	return 1;		
}

sub Connect {
	my $sock = shift;
	my $serv = shift;
	my $user = shift;
	my $pass = shift;
	my $cxml =
qq{<?xml version='1.0' encoding='ISO-8859-1'?>
<acx>
    <connect adapter='$serv'>
        <passwordAuthenticator username='$user' password='$pass'/>
    </connect>
</acx>
};
	XMLSend($sock, $cxml);
	my $data = XMLRecv($sock);
	
	# A connect request will usually result in a redirect
	if ($data =~ m/redirect.*<info>([^:]+):([0-9]{1,5})</sm) {
		return($1, $2);
	}
	
	# Return undefined if no redirect was found
	return;
}


##
# Network wrappers around XML transactions
##

sub XMLRecv {
	my $sock = shift;
	my $dlen = $sock->Recv(4, 10);
	return if ! $dlen;
	return $sock->Recv(unpack('N', $dlen), 10);
}

sub XMLSend {
	my $sock = shift;
	my $data = shift;
	return $sock->Send(pack('N', length($data)).$data);
}



1;
