
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Nop::Alpha;
use strict;
use base 'Msf::Nop';
use Pex::Utils;

my $advanced = { };
my $info = {
	'Name'    => 'Alpha Nop Generator',
	'Version' => '$Revision$',
	'Authors' => [ 'vlad902 <vlad902 [at] gmail.com>', ],
	'Arch'    => [ 'alpha' ],
	'Desc'    =>  'Alpha nop generator',
	'Refs'    => [ ],
};


sub new {
	my $class = shift; 
	return($class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_));
}

# XXX: Operate: ct*?, */v?, ext*?, min*?, ms*?, max*?, s[48]*?
# XXX: InsMemory (for lda and the like) 
# XXX: InsFPU??
my $table = [
	[ \&InsOperate,	[ 0, [ 0x10, 0x00 ] ], ],		# addl
	[ \&InsOperate,	[ 0, [ 0x10, 0x09 ] ], ],		# subl
	[ \&InsOperate,	[ 0, [ 0x10, 0x0f ] ], ],		# cmpbge
	[ \&InsOperate,	[ 0, [ 0x10, 0x1d ] ], ],		# cmpult
	[ \&InsOperate,	[ 0, [ 0x10, 0x20 ] ], ],		# addq
	[ \&InsOperate,	[ 0, [ 0x10, 0x29 ] ], ],		# subq
	[ \&InsOperate,	[ 0, [ 0x10, 0x2d ] ], ],		# cmpeq
	[ \&InsOperate,	[ 0, [ 0x10, 0x3d ] ], ],		# cmpule
	[ \&InsOperate,	[ 0, [ 0x10, 0x4d ] ], ],		# cmplt
	[ \&InsOperate,	[ 0, [ 0x10, 0x6d ] ], ],		# cmple
	[ \&InsOperate,	[ 0, [ 0x11, 0x00 ] ], ],		# and
	[ \&InsOperate,	[ 0, [ 0x11, 0x08 ] ], ],		# bic (andnot)
	[ \&InsOperate,	[ 0, [ 0x11, 0x14 ] ], ],		# cmovlbs
	[ \&InsOperate,	[ 0, [ 0x11, 0x16 ] ], ],		# cmovlbc
	[ \&InsOperate,	[ 0, [ 0x11, 0x20 ] ], ],		# bis (or)
	[ \&InsOperate,	[ 0, [ 0x11, 0x24 ] ], ],		# cmoveq
	[ \&InsOperate,	[ 0, [ 0x11, 0x26 ] ], ],		# cmovne
	[ \&InsOperate,	[ 0, [ 0x11, 0x28 ] ], ],		# ornot
	[ \&InsOperate,	[ 0, [ 0x11, 0x40 ] ], ],		# xor
	[ \&InsOperate,	[ 0, [ 0x11, 0x44 ] ], ],		# cmovlt
	[ \&InsOperate,	[ 0, [ 0x11, 0x46 ] ], ],		# cmovge
	[ \&InsOperate,	[ 0, [ 0x11, 0x48 ] ], ],		# eqv (xornot)
	[ \&InsOperate,	[ 0, [ 0x11, 0x64 ] ], ],		# cmovle
	[ \&InsOperate,	[ 0, [ 0x11, 0x66 ] ], ],		# cmovgt
	[ \&InsOperate,	[ 0, [ 0x12, 0x30 ] ], ],		# zap 
	[ \&InsOperate,	[ 0, [ 0x12, 0x31 ] ], ],		# zapnot
	[ \&InsOperate,	[ 0, [ 0x12, 0x34 ] ], ],		# srl
	[ \&InsOperate,	[ 0, [ 0x12, 0x39 ] ], ],		# sll
	[ \&InsOperate,	[ 0, [ 0x12, 0x3c ] ], ],		# sra
	[ \&InsOperate,	[ 0, [ 0x13, 0x00 ] ], ],		# mull
	[ \&InsOperate,	[ 0, [ 0x13, 0x20 ] ], ],		# mulq
	[ \&InsOperate,	[ 0, [ 0x13, 0x30 ] ], ],		# umulh
	[ \&InsBranch,	[ 0x30 ], ],				# br
	[ \&InsBranch,	[ 0x31 ], ],				# fbeq
	[ \&InsBranch,	[ 0x32 ], ],				# fblt
	[ \&InsBranch,	[ 0x33 ], ],				# fble
	[ \&InsBranch,	[ 0x35 ], ],				# fbne
	[ \&InsBranch,	[ 0x36 ], ],				# fbge
	[ \&InsBranch,	[ 0x37 ], ],				# fbgt
	[ \&InsBranch,	[ 0x38 ], ],				# blbc
	[ \&InsBranch,	[ 0x39 ], ],				# beq
	[ \&InsBranch,	[ 0x3a ], ],				# blt
	[ \&InsBranch,	[ 0x3b ], ],				# ble
	[ \&InsBranch,	[ 0x3c ], ],				# blbs
	[ \&InsBranch,	[ 0x3d ], ],				# bne
	[ \&InsBranch,	[ 0x3e ], ],				# bge
	[ \&InsBranch,	[ 0x3f ], ],				# bgt
];

# Returns valid destination register number between 0 and 31 excluding $sp.
# XXX: $gp/$ra/$fp???
sub get_dst_reg {
	my $reg = int(rand(31));
	$reg += ($reg >= 30);

	return $reg;
}

# Any register.
sub get_src_reg {
	return int(rand(32));
}

sub InsOperate {
	my $ref = shift;

	my $dst = get_dst_reg();
	my $ver = $ref->[0];

# 0, ~1, !2, ~3, !4
# Use one src reg with an unsigned 8-bit immediate (non-0)
	if(($ver == 0 && int(rand(2))) || $ver == 1)
	{
		return pack("V", (($ref->[1][0] << 26) | (get_src_reg() << 21) | ((int(rand((1 << 8) - 1)) + 1) << 13) | (1 << 12) | ($ref->[1][1] << 5) | $dst));
	}
# Use two src regs
	else
	{
		return pack("V", (($ref->[1][0] << 26) | (get_src_reg() << 21) | (get_src_reg() << 16) | ($ref->[1][1] << 5) | $dst));
	}
}

sub InsBranch {
	my $ref = shift;
	my $len = shift;

	$len = ($len / 4) - 1; 

	return if(! $len);
	$len = 0xfffff if($len > 0x100000);

	return pack("V", (($ref->[0] << 26) | (get_src_reg() << 21) | (int(rand($len - 1) + 1))));
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
