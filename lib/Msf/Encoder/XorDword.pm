

use strict;
package Msf::Encoder::XorDword;
use base 'Msf::Encoder';
use Pex::Encoding::XorDword;

sub EncodePayload {
  my $self = shift;
  my $rawshell = shift;
  my $badChars = shift;

  my $xorkey = Pex::Encoding::XorDword->KeyScan($rawshell, $badChars);
  if(!$xorkey) {
    $self->PrintDebugLine(3, 'Failed to find xor key');
    return;
  }

  my $xordat = Pex::Encoding::XorDword->Encode($xorkey, $rawshell);

  my $shellcode = $self->_GenEncoder($xorkey, length($xordat), $badChars) . $xordat;

  my $pos = Pex::Text::BadCharIndex($badChars, $shellcode);
  if($pos != -1) {
    $self->PrintDebugLine(4, Pex::Text::BufferC($shellcode));
    $self->PrintDebugLine(3, 'Bad char at pos ' . $pos);
    $self->PrintDebugLine(4, sprintf('Bad byte %i', ord(substr($shellcode, $pos, 1))));
    return;
  }
  return($shellcode);

}

1;
