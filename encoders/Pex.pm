
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Encoder::Pex;
use strict;
use base 'Msf::Encoder::XorDword';
use Pex::Encoder;

my $advanced = {
};

my $info = {
  'Name'    => 'Pex Jmp/Call Double Word Xor Encoder',
  'Version' => '$Revision$',
  'Authors' =>
    [
      'H D Moore <hdm [at] metasploit.com>',
      'spoonm <ninjatools [at] hush.com>',
    ],
  'Arch'    => [ 'x86' ],
  'OS'      => [ ],
  'Description'  =>  'Dynamically generated dword xor encoder (jmp/call)',
  'Refs'    => [ ],
};

sub new {
  my $class = shift; 
  return($class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_));
}

# Variable Length Decoder Using jmp/call 26/29 bytes.
# Uses smaller encoder if payload is <= 512 bytes
sub _GenEncoder {
  my $self = shift;
  my $xor = shift;
  my $len = shift;
  my $xorkey = pack('V', $xor);
  my $l = Pex::Encoder::PackLength($len);

  # spoon's smaller variable-length encoder
  my $decoder;
  if($l->{'negSmall'}) {
    # 26 bytes
    $decoder =
      "\xeb\x13".                         # jmp SHORT 0x15 (xor_end)
      "\x5e".                             # xor_begin: pop esi
      "\x31\xc9".                         # xor ecx,ecx
      "\x83\xe9". $l->{'negLengthByte'} . # sub ecx, BYTE -xorlen
      "\x81\x36". $xorkey .               # xor_xor: xor DWORD [esi],xorkey
      "\x83\xee\xfc".                     # sub $esi,-4
      "\xe2\xf5".                         # loop 0x8 (xor_xor)
      "\xeb\x05".                         # jmp SHORT 0x1a (xor_done)
      "\xe8\xe8\xff\xff\xff";             # xor_end: call 0x2 (xor_begin)
                                          # xor_done:
  }
  else {
    # 29 bytes
    $decoder =
      "\xeb\x16".                         # jmp SHORT 0x18 (xor_end)
      "\x5e".                             # xor_begin: pop esi
      "\x31\xc9".                         # xor ecx,ecx
      "\x81\xe9". $l->{'negLength'} .     # sub ecx, -xorlen
      "\x81\x36". $xorkey .               # xor_xor: xor DWORD [esi],xorkey
      "\x83\xee\xfc".                     # sub $esi,-4
      "\xe2\xf5".                         # loop 0xb (xor_xor)
      "\xeb\x05".                         # jmp SHORT 0x1d (xor_done)
      "\xe8\xe5\xff\xff\xff";             # xor_end: call 0x2 (xor_begin)
                                          # xor_done:
  }

  return($decoder);
}

1;
