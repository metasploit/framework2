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
	my $self = shift;
	my $len  = shift;

	return if($len <= 0);

	# our output sled string
	my $data;
	# our last byte (current state)
	my $prev = 256;
	# the current stream len ( length($data) )
	my $dlen = 0;

	#
	# initialize the byte count table
	#
	my $counts = [ ];
	for(my $i = 0; $i < 256; $i++) {
		$counts->[$i] = 0;
	}

	#
	# The badreg mask
	#
	my $mask;
	foreach my $r (@{$self->_BadRegs}) {
		$mask |= 1 << $r;
	}
	$mask <<= 16;

	#
	# The bad byte lookup table
	#
	my $badbytes = [ ];
	foreach my $bad (split('', $self->_BadChars)) {
		$badbytes->[ord($bad)] = 1;
	}

	my $table = $self->_Table;

	while($len--) {
		#
		# Find our next byte
		#

		# current best value
		my $low = -1;
		# table were we store the current best choices
		my @lows;

		# array of arrays to save memory, iterate
		foreach my $nt (@{$table->[$prev]}) {
		foreach my $e (@{$nt}) {
			# modifies a register we want to save
			next if($e & $mask);
			# requried length is more than our current stream length
			next if(($e >> 8 & 0xff) > $dlen);

			my $b = $e & 0xff;
			# the choice is a bad byte
			next if($badbytes->[$b]);

			# a better value...
			if($low == -1 || $low > $counts->[$b]) {
				$low = $counts->[$b];
				@lows = ($b);
			}
			# an equally good value...
			elsif($low == $counts->[$b]) {
				push(@lows, $b);
			}
		}}

		# we failed to find even 1 possiblity, bummer, abort :(
		return(-1) if($low == -1);

		# return a random pick of our best choices...
		$prev = $lows[int(rand(@lows))];

		#
		# Ok, we found our next byte
		#

		# up the counter for the byte we just added
		$counts->[$prev]++;

		# prepend it to our seld
		$data = chr($prev) . $data;

		# up our sled count
		$dlen++;
	}
	return($data);
}

1;
