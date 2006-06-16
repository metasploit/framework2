
###############

##
#         Name: Alpha.pm
#       Author: vlad902 <vlad902 [at] gmail.com>
#      Version: $Revision$
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Pex::Alpha;
use strict;

# Register encodings.
my %registers =	(
			"v0",  0, "t0",  1, "t1",  2, "t2",  3,
			"t3",  4, "t4",  5, "t5",  6, "t6",  7,
			"t7",  8, "s0",  9, "s1", 10, "s2", 11,
			"s3", 12, "s4", 13, "s5", 14, "s6", 15,
			"a0", 16, "a1", 17, "a2", 18, "a3", 19,
			"a4", 20, "a5", 21, "t8", 22, "t9", 23,
			"t10",24, "t11",25, "ra", 26, "pv", 27,
			"at", 28, "gp", 29, "sp", 30,"zero",31,
			"fp", 15, "t12",28,
		);


sub Addq {
  my $src = shift;
  my $constant = shift;
  my $dst = shift;

  return pack("V", ((16 << 26) | ($registers{$src} << 21) | ($constant & 0xff) << 13 | (1 << 12) | (32 << 5) | $registers{$dst}));
}

# Negative number 64-bit integer overflow problems.
sub Ldah {
  my $src = shift;
  my $constant = shift;
  my $dst = shift;

  return pack("V", ((9 << 26) | ($registers{$dst} << 21) | ($registers{$src} << 16) | ($constant >> 16)));
}

sub Lda {
  my $src = shift;
  my $constant = shift;
  my $dst = shift;

  return pack("V", ((8 << 26) | ($registers{$dst} << 21) | ($registers{$src} << 16) | ($constant & 0xffff)));
}

# Acts as set/mov, does size optimizations where possible.
sub Set {
  my $constant = shift;
  my $dst = shift;

# XXX: Brain dead algo, split into two parts, upper and lower word.
  if($constant <= 255 && $constant >= 0)
  {
    return Addq("zero", $constant, $dst);
  }
  elsif($constant <= 0xffff && $constant >= 0)
  {
    return Lda("zero", $constant, $dst);
  }
  elsif($constant & 0xffff)
  {
    if($constant & 0x8000)
    {
      return Ldah("zero", $constant + (1 << 16), $dst) . Lda($dst, $constant, $dst);
    }
    else
    {
      return Ldah("zero", $constant, $dst) . Lda($dst, $constant, $dst);
    }
  }
  else
  {
    return Ldah("zero", $constant, $dst);
  }
}

1;
