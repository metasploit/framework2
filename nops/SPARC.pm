
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
  [ \&Insarithmetic, [ 1, 16 ], ],			# addcc
  [ \&Insarithmetic, [ 1, 17 ], ],			# andcc
  [ \&Insarithmetic, [ 1, 18 ], ],			# orcc
  [ \&Insarithmetic, [ 1, 19 ], ],			# xorcc
  [ \&Insarithmetic, [ 1, 20 ], ],			# subcc
  [ \&Insarithmetic, [ 1, 21 ], ],			# andncc
  [ \&Insarithmetic, [ 1, 22 ], ],			# orncc
  [ \&Insarithmetic, [ 1, 23 ], ],			# xnorcc
  [ \&Insarithmetic, [ 1, 24 ], ],			# addxcc
  [ \&Insarithmetic, [ 1, 26 ], ],			# umulcc
  [ \&Insarithmetic, [ 1, 27 ], ],			# smulcc
  [ \&Insarithmetic, [ 1, 28 ], ],			# subxcc
  [ \&Insarithmetic, [ 0, 30 ], ],			# udivcc
  [ \&Insarithmetic, [ 0, 31 ], ],			# sdivcc
  [ \&Insarithmetic, [ 2, 37 ], ],			# sll
  [ \&Insarithmetic, [ 2, 38 ], ],			# srl
  [ \&Insarithmetic, [ 2, 39 ], ],			# sra
  [ \&Insbranch, [ 0 ] ],				# bn[,a]
  [ \&Insbranch, [ 1 ] ],				# be[,a]
  [ \&Insbranch, [ 2 ] ],				# ble[,a]
  [ \&Insbranch, [ 3 ] ],				# bl[,a]
  [ \&Insbranch, [ 4 ] ],				# bleu[,a]
  [ \&Insbranch, [ 5 ] ],				# bcs[,a]
  [ \&Insbranch, [ 6 ] ],				# bneg[,a]
  [ \&Insbranch, [ 7 ] ],				# bvs[,a]
  [ \&Insbranch, [ 8 ] ],				# ba[,a]
  [ \&Insbranch, [ 9 ] ],				# bne[,a]
  [ \&Insbranch, [ 10 ] ],				# bg[,a]
  [ \&Insbranch, [ 11 ] ],				# bge[,a]
  [ \&Insbranch, [ 12 ] ],				# bgu[,a]
  [ \&Insbranch, [ 13 ] ],				# bcc[,a]
  [ \&Insbranch, [ 14 ] ],				# bpos[,a]
  [ \&Insbranch, [ 15 ] ],				# bvc[,a]
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

sub Insbranch {
  my $ref = shift;
  my $len = shift;

# We jump to 1 instruction before the payload so in cases where the delay slot of a branch with the the anull bit set that is not taken the first instruction of the
#   payload is not anulled. 
  $len = ($len / 4) - 1;

  return if(! $len);
  $len = 0x3fffff if($len >= 0x400000);

  return pack("N", ((int(rand(2)) << 29) | ($ref->[0] << 25) | (2 << 22) | $len)); 
#  return pack("N", ((int(rand(2)) << 29) | ($ref->[0] << 25) | (2 << 22) | int(rand($len - 1)) + 1)); 
}

sub Nops {
  my $self = shift;
  my $length = shift;
  my $backup_length = $length;

  my $exploit = $self->GetVar('_Exploit');
  my $random  = $self->GetLocal('RandomNops');
  my $badChars = $exploit->PayloadBadChars;
  my ($nop, $tempnop, $count, $rand);

  if(! $random)
  {
    $length = 4;
  }

  for($count = 0; length($nop) < $length; $count++)
  {
    $rand = int(rand(scalar(@{$table})));

    $tempnop = $table->[$rand]->[0]($table->[$rand]->[1], $length - length($nop));

    if(!Pex::Utils::ArrayContains([split('', $tempnop)], [split('', $badChars)]))
    {
      $nop .= $tempnop;
      $count = 0;
    }

    if($count > $length + 500)
    {
      if(length($nop) == 0)
      {
        $self->PrintDebugLine(3, "Iterated $count times with no nop match.");
        return;
      }

      $self->PrintDebugLine(4, "Iterated $count times with no nop match (length(\$nop) = " . sprintf("%i", length($nop)) . ")");
    }
  }

  if(! $random)
  {
    return $nop x ($backup_length / 4);
  }

  return $nop;
}

1;
