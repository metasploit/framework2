#!/usr/bin/perl
use strict;

package Msf::Nop::OptyNop2;
use base 'Msf::Nop::OptyNop2Tables';

sub _BadRegs {
	# esp, ebp
	return([4, 5]);
}
sub _BadChars {
	return('');
}

sub _GenerateSled {
	my $s = shift;
	my $l = shift;

	return if($l <= 0);

	my ($b, $m);
	my $p = 256;
	my $pc = 0;
	my $c = [ ];
	for(my $i = 0; $i < 256; $i++) {
		$c->[$i] = 0;
	}
	foreach my $r (@{$s->_BadRegs}) {
		$m |= 1 << $r;
	}

	while($l--) {
		$p = $s->f($m, $pc, $p, $c);
		return if($p == -1);
		$b = chr($p) . $b;
		$pc++;
	}
	return($b);
}

sub f {
	my $s  = shift;
	my $m  = shift;
	my $pc = shift;
	my $p  = shift;
	my $c  = shift;

	my $nt = $s->_Table->[$p];
	my $nl = @{$nt};

	return(-1) if($nl == 0);

	my @s;
	for(my $i = 0; $i < $nl; $i += 3) {
		push(@s, $i);
	}

	Pex::Utils::FisherYates(\@s);

	my $lv = -1;
	my $l  = -1;  

	foreach my $i (@s) {
		next if($nt->[$i] & $m);
		next if($nt->[$i + 1] > $pc);
		next if(Pex::Text::BadCharCheck($s->_BadChars, chr($nt->[$i + 2])));

		if($lv == -1 || $lv > $c->[$nt->[$i + 2]]) {
			$l  = $i + 2;
			$lv = $c->[$nt->[$l]];
		}
	}


	return(-1) if($l == -1);

	$c->[$nt->[$l]]++;
	return($nt->[$l]);
}

1;
