
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Nop::SPARC;
use strict;
use base 'Msf::Nop';
use Pex::Utils;
use Pex::SPARC;

my $info = {
  'Name'    => 'SPARC Nop Generator',
  'Version' => '$Revision$',
  'Authors' => [ 'vlad902 <vlad902 [at] gmail.com>', ],
  'Arch'    => [ 'sparc' ],
  'Desc'    =>  'Sparc nop generator',
  'Refs'    => [ ],
};

my $advanced = { };

sub new {
  my $class = shift; 
  return($class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_));
}

my $table = [
  [ \&Inssethi, [ ], ],					# sethi
  [ \&Insarithmetic, [ 1, 0 ], ],			# add
  [ \&Insarithmetic, [ 1, 1 ], ],			# and
  [ \&Insarithmetic, [ 1, 2 ], ],			# or
  [ \&Insarithmetic, [ 1, 3 ], ],			# xor
  [ \&Insarithmetic, [ 1, 4 ], ],			# sub
  [ \&Insarithmetic, [ 1, 5 ], ],			# andn
  [ \&Insarithmetic, [ 1, 6 ], ],			# orn
  [ \&Insarithmetic, [ 1, 7 ], ],			# xnor
  [ \&Insarithmetic, [ 1, 8 ], ],			# addx
  [ \&Insarithmetic, [ 1, 10 ], ],			# umul 
  [ \&Insarithmetic, [ 1, 11 ], ],			# smul 
  [ \&Insarithmetic, [ 1, 12 ], ],			# subx
  [ \&Insarithmetic, [ 0, 14 ], ],			# udiv
  [ \&Insarithmetic, [ 0, 15 ], ],			# sdiv
  [ \&Insarithmetic, [ 2, 37 ], ],			# sll
  [ \&Insarithmetic, [ 2, 38 ], ],			# srl
  [ \&Insarithmetic, [ 2, 39 ], ],			# sra
];

# Returns valid destination register number between 0 and 31 excluding %sp
sub get_dst_reg {
  my $reg = int(rand(31));
  $reg += ($reg >= 14);

  return $reg;
}

# Any register.
sub get_src_reg {
  return int(rand(32));
}

sub Inssethi {
  return pack("N", ((get_dst_reg() << 25) | (4 << 22) | int(rand(1 << 22))));
}

sub Insarithmetic {
  my $ref = shift;

# Use one src reg with a signed 13-bit immediate (non-0)
  if(($ref->[0] == 0 || int(rand(2))) && $ref->[0] != 2)
  {
    return pack("N", ((2 << 30) | (get_dst_reg() << 25) | ($ref->[1] << 19) | (get_src_reg() << 14) | (1 << 13) | (int(rand((1 << 13) - 1)) + 1)));
  }
# Use two src regs
  else
  {
    return pack("N", ((2 << 30) | (get_dst_reg() << 25) | ($ref->[1] << 19) | (get_src_reg() << 14) | get_src_reg()));
  }
}

sub Nops {
  my $self = shift;
  my $length = shift;

  my $exploit = $self->GetVar('_Exploit');
  my $random  = $self->GetLocal('RandomNops');
  my $badChars = $exploit->PayloadBadChars;
  my ($nop, $random, $tempnop);
    
# DEBUG DEBUG DEBUG
#  $nop = "\x91\xd0\x20\x01";

# XXX: $random support

  while(length($nop) < $length)
  {
    $random = int(rand(scalar(@{$table})));

    $tempnop = $table->[$random]->[0]($table->[$random]->[1]);

    if(!Pex::Utils::ArrayContains([split('', $tempnop)], [split('', $badChars)]))
    {
      $nop .= $tempnop;
    }
  }

  return $nop;
}


1;
