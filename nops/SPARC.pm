
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

my $advanced = { };
my $info = {
	'Name'    => 'SPARC Nop Generator',
	'Version' => '$Revision$',
	'Authors' => [ 'vlad902 <vlad902 [at] gmail.com>', ],
	'Arch'    => [ 'sparc' ],
	'Desc'    =>  'SPARC nop generator',
	'Refs'    => [ ],
};


sub new {
	my $class = shift; 
	return($class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_));
}

my $table = [
	[ \&InsSethi, [ ], ],					# sethi
	[ \&InsArithmetic, [ 0, 0 ], ],				# add
	[ \&InsArithmetic, [ 0, 1 ], ],				# and
	[ \&InsArithmetic, [ 0, 2 ], ],				# or
	[ \&InsArithmetic, [ 0, 3 ], ],				# xor
	[ \&InsArithmetic, [ 0, 4 ], ],				# sub
	[ \&InsArithmetic, [ 0, 5 ], ],				# andn
	[ \&InsArithmetic, [ 0, 6 ], ],				# orn
	[ \&InsArithmetic, [ 0, 7 ], ],				# xnor
	[ \&InsArithmetic, [ 0, 8 ], ],				# addx
	[ \&InsArithmetic, [ 0, 12 ], ],			# subx
	[ \&InsArithmetic, [ 0, 16 ], ],			# addcc
	[ \&InsArithmetic, [ 0, 17 ], ],			# andcc
	[ \&InsArithmetic, [ 0, 18 ], ],			# orcc
	[ \&InsArithmetic, [ 0, 19 ], ],			# xorcc
	[ \&InsArithmetic, [ 0, 20 ], ],			# subcc
	[ \&InsArithmetic, [ 0, 21 ], ],			# andncc
	[ \&InsArithmetic, [ 0, 22 ], ],			# orncc
	[ \&InsArithmetic, [ 0, 23 ], ],			# xnorcc
	[ \&InsArithmetic, [ 0, 24 ], ],			# addxcc
	[ \&InsArithmetic, [ 0, 28 ], ],			# subxcc
	[ \&InsArithmetic, [ 0, 32 ], ],			# taddcc
	[ \&InsArithmetic, [ 0, 33 ], ],			# tsubcc
	[ \&InsArithmetic, [ 0, 36 ], ],			# mulscc
	[ \&InsArithmetic, [ 2, 37 ], ],			# sll
	[ \&InsArithmetic, [ 2, 38 ], ],			# srl
	[ \&InsArithmetic, [ 2, 39 ], ],			# sra
	[ \&InsArithmetic, [ 4, 40 ], ],			# rdy
	[ \&InsArithmetic, [ 3, 48 ], ],			# wry
	[ \&InsBranch, [ 0 ] ],					# bn[,a]
	[ \&InsBranch, [ 1 ] ],					# be[,a]
	[ \&InsBranch, [ 2 ] ],					# ble[,a]
	[ \&InsBranch, [ 3 ] ],					# bl[,a]
	[ \&InsBranch, [ 4 ] ],					# bleu[,a]
	[ \&InsBranch, [ 5 ] ],					# bcs[,a]
	[ \&InsBranch, [ 6 ] ],					# bneg[,a]
	[ \&InsBranch, [ 7 ] ],					# bvs[,a]
	[ \&InsBranch, [ 8 ] ],					# ba[,a]
	[ \&InsBranch, [ 9 ] ],					# bne[,a]
	[ \&InsBranch, [ 10 ] ],				# bg[,a]
	[ \&InsBranch, [ 11 ] ],				# bge[,a]
	[ \&InsBranch, [ 12 ] ],				# bgu[,a]
	[ \&InsBranch, [ 13 ] ],				# bcc[,a]
	[ \&InsBranch, [ 14 ] ],				# bpos[,a]
	[ \&InsBranch, [ 15 ] ],				# bvc[,a]
# Removed for SPARCV7 support
#	[ \&InsArithmetic, [ 0, 10 ], ],			# umul 
#	[ \&InsArithmetic, [ 0, 11 ], ],			# smul 
#	[ \&InsArithmetic, [ 1, 14 ], ],			# udiv
#	[ \&InsArithmetic, [ 1, 15 ], ],			# sdiv
#	[ \&InsArithmetic, [ 0, 26 ], ],			# umulcc
#	[ \&InsArithmetic, [ 0, 27 ], ],			# smulcc
#	[ \&InsArithmetic, [ 1, 30 ], ],			# udivcc
#	[ \&InsArithmetic, [ 1, 31 ], ],			# sdivcc
];

# Returns valid destination register number between 0 and 31 excluding %sp and %fp
sub get_dst_reg {
	my $reg = int(rand(30));
	$reg += ($reg >= 14);
	$reg += ($reg >= 30);

	return $reg;
}

# Any register.
sub get_src_reg {
	return int(rand(32));
}

sub InsSethi {
	return pack("N", ((get_dst_reg() << 25) | (4 << 22) | int(rand(1 << 22))));
}

sub InsArithmetic {
	my $ref = shift;
	my $dst = get_dst_reg();
	my $ver = $ref->[0];

# WRY fix-ups.
	if($ver == 3)
	{
		$dst = 0;
		$ver = 1; 
	}

# 0, ~1, !2, ~3, !4
# Use one src reg with a signed 13-bit immediate (non-0)
	if(($ver == 0 && int(rand(2))) || $ver == 1)
	{
		return pack("N", ((2 << 30) | ($dst << 25) | ($ref->[1] << 19) | (get_src_reg() << 14) | (1 << 13) | (int(rand((1 << 13) - 1)) + 1)));
	}
# RDY
	elsif($ver == 4)
	{
# $ref->[1] could be replaced with a static value since this only encodes for one function but it's done this way for consistancy.
		return pack("N", ((2 << 30) | ($dst << 25) | ($ref->[1] << 19)));
	}
# Use two src regs
	else
	{
		return pack("N", ((2 << 30) | ($dst << 25) | ($ref->[1] << 19) | (get_src_reg() << 14) | get_src_reg()));
	}
}

sub InsBranch {
	my $ref = shift;
	my $len = shift;

# We jump to 1 instruction before the payload so in cases where the delay slot of a branch with the the anull bit set that is not taken the first instruction of the
#   payload is not anulled. 
	$len = ($len / 4) - 1;

	return if(! $len);
	$len = 0x3fffff if($len >= 0x400000);

#	return pack("N", ((int(rand(2)) << 29) | ($ref->[0] << 25) | (2 << 22) | $len)); 
	return pack("N", ((int(rand(2)) << 29) | ($ref->[0] << 25) | (2 << 22) | int(rand($len - 1)) + 1)); 
}

sub Nops {
	my $self = shift;
	my $length = shift;
	my $backup_length = $length;

	my $exploit = $self->GetVar('_Exploit');
	my $random  = $self->GetVar('RandomNops');
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

		if($count > $length + 10000)
		{
			$self->PrintDebugLine(3, "Iterated $count times with no nop match.");
			return;
		}
	}

	if(! $random)
	{
		$nop = $nop x ($backup_length / 4);
	}

	return $nop;
}

1;
