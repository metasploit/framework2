
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
use Pex::x86;

my $advanced = {
};

my $info = {
  'Name'    => 'Pex Call $+4 Double Word Xor Encoder',
  'Version' => '$Revision$',
  'Authors' =>
    [
      'H D Moore <hdm [at] metasploit.com>',
      'spoonm <ninjatools [at] hush.com>',
    ],
  'Arch'    => [ 'x86' ],
  'OS'      => [ ],
  'Description'  =>  'Dynamically generated dword xor encoder',
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
  my $badchars = shift;
  my $xorkey = pack('V', $xor);

  # spoon's smaller variable-length encoder (updated to use call $+4 by vlad902)
  my $decoder =
    Pex::x86::Sub(-((($len -1) / 4) + 1), "ecx", $badchars).
    "\xe8\xff\xff\xff".			# call $+4
    "\xff\xc0".				# inc eax
    "\x5e".				# pop esi
    "\x81\x76\x0e" . $xorkey.		# xor_xor: xor [esi + 0x0e], $xorkey 
    "\x83\xee\xfc".			# sub esi, -4
    "\xe2\xf4";				# loop xor_xor
    
  return($decoder);
}

1;
