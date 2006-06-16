
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Encoder::Countdown;
use strict;
# XXX:
use base 'Msf::Encoder::XorDword';
use Pex::x86;

my $advanced = {
};

my $info = {
  'Name'    => 'x86 Call $+4 countdown xor encoder',
  'Version' => '$Revision$',
  'Authors' =>
    [
      'vlad902 <vlad902 [at] gmail.com>',
    ],
  'Arch'    => [ 'x86' ],
  'OS'      => [ ],
  'Description'  =>  'Tiny countdown byte xor encoder',
  'Refs'    => [ ],
};

sub new {
  my $class = shift; 
  return($class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_));
}

sub EncodePayload {
  my $self = shift;
  my $payload = shift;
  my $badchars = shift;

  my $decoder =
    Pex::x86::Mov(length($payload) - 1, "ecx", $badchars).
    "\xe8\xff\xff\xff".			# call $+4
    "\xff\xc1".				# inc ecx
    "\x5e".				# pop esi
    "\x30\x4c\x0e\x07".	 		# xor_xor: xor [esi + ecx + 0x07], cl 
    "\xe2\xfa";				# loop xor_xor
    
  return($decoder . CountdownXor($payload));
}

sub CountdownXor {
  my @payload = split('', shift); 
  my $xored;

  for(my $count=0; $count < scalar @payload; $count++)
  {
    $xored .= pack("C", (unpack("C", $payload[$count]) ^ ($count + 1)));
  }

  return $xored;
}

1;
