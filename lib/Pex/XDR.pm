
###############

##
#         Name: XDR.pm
#       Author: vlad902 <vlad902 [at] gmail.com>
#      Version: $Revision$
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Pex::XDR;
use strict;

use base 'Msf::Base';

sub Int {
	my $int = shift;
	return pack("N", $int);
}
sub UInt {
	my $int = shift;
	return pack("N", $int);
}
sub Enum {
	my $int = shift;
	return pack("N", $int);
}

sub Bool {
	my $int = shift;

	if($int < 0 || $int > 1)
	{
		PrintLine("Bool() took $int, not a binary value!");
		return;
	}
	return pack("N", $int);
}

# XXX: HyperInt + UHyperInt

# Fixed-length Opaque (ie. opaque foo[8192])
sub FOpaque {
	my $str = shift;
# XXX:	my $len = __alignup(shift, 4);???
	my $len = shift;

	$str .= chr(0) x ($len - length($str)); 

	return $str;
}

# Variable-length Opaque (ie. opaque foo<8192>)
sub VOpaque {
	my $str = shift;
	my $max_len = shift || (2 ** 32) - 1; 

	if(length($str) > $max_len)
	{
		PrintLine(sprintf("VOpaque() took opaque data of %i bytes with a $max_len maximum!", length($str)));
		return;
	}

	my $len = length($str);
	$str .= chr(0) x (4 - (length($str) % 4)) if($len % 4);

	return UInt($len) . $str;
}

sub String {
	return VOpaque(@_);
}

# XXX: FArray

# Variable-length array
sub VArray {
	my $data = shift;
	my $ref = shift;
	my $max_len = shift || (2 ** 32) - 1;

	my @tbl = @{$data};

	if(scalar @tbl > $max_len)
	{
		PrintLine(sprintf("VArray() took array of %i elements with a $max_len maximum!", scalar @tbl));
	}

	my $str = UInt(scalar @tbl);
	foreach(@tbl)
	{
		$str .= &$ref($_);
	}

	return $str;
}

sub Void {
	return;
}

1;
