
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Encoder::PexFnstenvMov;
use strict;
use base 'Msf::Encoder::XorDword';
use Pex::Encoder;
use Pex::x86;

my $advanced = {
};

my $info = {
  'Name'    => 'Pex Variable Length Fnstenv/mov Double Word Xor Encoder',
  'Version' => '$Revision$',
  'Authors' => [ 'spoonm <ninjatools [at] hush.com>', ],
  'Arch'    => [ 'x86' ],
  'OS'      => [ ],
  'Description'  =>  'Variable-length fnstenv/mov dword xor encoder',
  'Refs'    => [ ],
};

sub new {
  my $class = shift; 
  return($class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_));
}

sub _GenEncoder {
  my $self = shift;
  my $xor = shift;
  my $len = shift;
  my $xorkey = pack('V', $xor);


  # spoon's smaller variable-length fnstenv encoder
  my $decoder =
    "\xd9\xee".                         # fldz
    "\xd9\x74\x24\xf4".                 # fnstenv [esp - 12]
    "\x5b".                             # pop ebx
    Pex::x86::mov((($len - 1) / 4) + 1, "ecx").
    "\x81\x73\x17". $xorkey .           # xor_xor: xor DWORD [ebx + 24], xorkey
    "\x83\xeb\xfc".                     # sub ebx,-4
    "\xe2\xf4";                         # loop xor_xor

  return($decoder);
}

1;
