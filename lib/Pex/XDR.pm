
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

sub Encode_int {
	my $int = shift;

	return pack("N", $int);
}
sub Decode_int {
	my $str_ref = shift;

	my $int = unpack("N", $$str_ref);
	$$str_ref = substr($$str_ref, 4);

	return $int;
}

sub Encode_bool {
	my $int = shift;

	if($int < 0 || $int > 1)
	{
		PrintLine("Encode_bool() took $int, not a binary value!");
	}

	return pack("N", $int);
}
sub Decode_bool {
	my $str_ref = shift;

	my $int = unpack("N", $$str_ref);
	$$str_ref = substr($$str_ref, 4);

	if($int < 0 || $int > 1)
	{
		PrintLine("Decode_bool() recieved a non-binary value!");
	}

	return $int;
}

sub Encode_lchar {
	my $char = shift;

	if($char & 0x80)
	{
		$char |= 0xffffff00;
	}

	return pack("N", $char);
}
sub Decode_lchar {
	my $str_ref = shift;

	my $char = unpack("N", $$str_ref);
	$$str_ref = substr($$str_ref, 4);

	return chr($char & 0xff);
}

# XXX: HyperInt

# XXX: Decode_fopaque

# Fixed-length Opaque (ie. opaque foo[8192])
sub Encode_fopaque {
	my $str = shift;
# XXX:	my $len = __alignup(shift, 4);???
	my $len = shift;

	$str .= chr(0) x ($len - length($str)); 

	return $str;
}

# Variable-length Opaque (ie. opaque foo<8192>)
sub Encode_vopaque {
	my $str = shift;
	my $max_len = shift || (2 ** 32) - 1; 

	if(length($str) > $max_len)
	{
		PrintLine(sprintf("Encode_vopaque() took opaque data of %i bytes with a $max_len maximum!", length($str)));
		return;
	}

	my $len = length($str);
	$str .= chr(0) x (4 - (length($str) % 4)) if($len % 4);

	return Encode_int($len) . $str;
}

sub Decode_vopaque {
	my $str_ref = shift;

	my $num = unpack("N", $$str_ref); 
	$$str_ref = substr($$str_ref, 4);

	my $data = substr($$str_ref, 0, $num);
	$$str_ref = substr($$str_ref, __alignup($num, 4));

	return $data;
}

sub Encode_string { Encode_vopaque(@_); }
sub Decode_string { Decode_vopaque(@_); } 

# XXX: FArray

# Variable-length array
sub Encode_varray {
	my $data = shift;
	my $ref = shift;
	my $max_len = shift || (2 ** 32) - 1;

	my @tbl = @{$data};

	if(scalar @tbl > $max_len)
	{
		PrintLine(sprintf("Encode_varray() took array of %i elements with a $max_len maximum!", scalar @tbl));
	}

	my $str = Encode_int(scalar @tbl);
	foreach(@tbl)
	{
		$str .= &$ref($_);
	}

	return $str;
}

sub Decode_varray {
	my $str_ref = shift;
	my $ref = shift;

	my $num = unpack("N", $$str_ref); 
	$$str_ref = substr($$str_ref, 4);

	my @return_val;
	while($num)
	{
		push(@return_val, &$ref($str_ref));

		$num--;
	}

	return @return_val;
}

sub __alignup {
	my $num = shift;
	my $align = shift;

	return (($num + $align - 1) & -$align);
}

1;
