
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Encoder::OSXPPCLongXORTag;
use strict;
use base 'Msf::Encoder';
use Pex::Encoder;
use Pex::Encoding::XorDword;

my $advanced =  {};

my $info = {
    'Name'    => 'MacOS X PPC LongXOR Tag Encoder',
    'Version' => '1.0',
    'Authors' => [ 'Dino Dai Zovi <ddz [at] theta44.org>',
		           'H D Moore <hdm [at] metasploit.com>' ],
    'Arch'    => [ 'ppc' ],
    'OS'      => [ 'osx' ],
    'Description'  =>  "This is based on ghandi's PPC dword xor decoder, now tag-based and smaller",
    'Refs'    => [ ],
};

sub new {
    my $class = shift; 
    return($class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_));
}

sub EncodePayload {
    my $self     = shift;
    my $payload  = shift;
    my $badchars = shift;

    my $xor_key   = Pex::Encoding::XorDword->KeyScan($payload, $badchars);
    my $xor_data  = Pex::Encoding::XorDword->Encode($xor_key, $payload);

    # Flip the key endian-ness
    $xor_key = unpack('V', pack('N', $xor_key));

    my $encoder = pack("N*", 
	   0x7ca52a79,     # 0x1da4 <main>:          xor.    r5,r5,r5
	   0x4082fffd,     # 0x1da8 <main+4>:        bnel+   0x1da4 <main>
	   0x7fe802a6,     # 0x1dac <main+8>:        mflr    r31
	   0x3bffd00c,     # 0x1db0 <main+12>:       addi    r31,r31,-12276
	   0x38a53030,     # 0x1db4 <main+16>:       addi    r5,r5,12336
	   0x3cc00102,     # 0x1db8 <main+20>:       lis     r6, hi16(key)
	   0x60c60304,     # 0x1dbc <main+24>:       ori     r6,r6, lo16(key)
	   0x811f3030,     # 0x1dc0 <main+28>:       lwz     r8,12336(r31)
	   0x7d043279,     # 0x1dc4 <main+32>:       xor.    r4,r8,r6
	   0x909f3030,     # 0x1dc8 <main+36>:       stw     r4,12336(r31)
	   0x7c05f8ac,     # 0x1dcc <main+40>:       dcbf    r5,r31
	   0x7cff04ac,     # 0x1dd0 <main+44>:       sync
	   0x7c05ffac,     # 0x1dd4 <main+48>:       icbi    r5,r31
	   0x3bc5cfd4,     # 0x1dd8 <main+52>:       addi    r30,r5,-12332
	   0x7ffff214,     # 0x1ddc <main+56>:       add     r31,r31,r30
	   0x4082ffe0,     # 0x1de0 <main+60>:       bne+    0x1dc0 <main+28>
	   0x4cff012c,     # 0x1de4 <main+64>:       isync
	);
	
	# patch the xor key (high and low)
	substr($encoder, 22, 2, substr(pack('N', $xor_key), 0, 2));
	substr($encoder, 26, 2, substr(pack('N', $xor_key), 2, 2));

    # the tag is the xor key... a null dword will cause the decoder to stop prematurely
	if (index($xor_data, pack('N', $xor_key)) != -1) {
		$self->PrintDebugLine(3, "Bailing out because a NULL dword was found in the payload");
		return;
	}
	
	if (Pex::Text::BadCharIndex($badchars, $encoder) == -1) {
		return $encoder.$xor_data.pack('N', $xor_key);
	}
	
	return;
}

1;