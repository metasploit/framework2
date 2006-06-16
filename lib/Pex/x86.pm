
###############

##
#         Name: x86.pm
#       Author: spoonm <ninjatools [at] hush.com>
#       Author: vlad902 <vlad902 [at] gmail.com>
#      Version: $Revision$
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Pex::x86;
use strict;

sub JmpShort {
  my $dist = RelNumber(shift, -2);
  return("\xeb" . PackLSB($dist));
}

sub call {
  my $dist = RelNumber(shift, -5);
  return("\xe8" . PackDword($dist));
}

sub RelNumber {
  my $number = shift;
  my $delta = @_ ? shift : 0;

  if(substr($number, 0, 2) eq '$+') {
    $number = substr($number, 2);
  }
  elsif(substr($number, 0, 2) eq '$-') {
    $number = -1 * substr($number, 2);
  }
  else {
    $delta = 0;
  }

  if(substr($number, 0, 2) eq '0x') {
    $number = hex($number);
  }
  $number += $delta;

  return($number);
}

sub Pack8 {
  my $number = shift;
  $number = RelNumber($number);
  return(PackLSB($number));
}
sub Pack16 {
  my $number = shift;
  $number = RelNumber($number);
  return(PackLSW($number));
}
sub Pack32 {
  my $number = shift;
  $number = RelNumber($number);
  return(Pack($number));
}

sub PackLSB {
  my $number = shift;
  return(substr(PackDword($number), 0, 1));
}
sub PackMSB {
  my $number = shift;
  return(substr(PackDword($number), 3, 1));
}

sub PackLSW {
  my $number = shift;
  return(substr(PackDword($number), 0, 2));
}
sub PackMSW {
  my $number = shift;
  return(substr(PackDword($number), 2, 2));
}

sub PackDword {
  my $number = shift;
  return(pack('V', $number));
}

sub Unpack {
  my $packed = shift;
  $packed .= "\x00" x (4 - length($packed));
  return(unpack('V', $packed));
}

sub UnpackSigned {
  my $packed = shift;
  my $signExtend = 0;
  if(ord(substr($packed, -1, 1) & "\x80") == 0x80) {
    $packed = ~$packed;
    $signExtend = 1;
  }
  $packed .= "\x00" x (4 - length($packed));
  my $value = unpack('V', $packed);
  if($signExtend) {
    $value = ($value + 1) * -1;
  }
  return($value);
}

my $regs = {
  'al' => 0, 'ax' => 0, 'eax' => 0, 'es' => 0,
  'cl' => 1, 'cx' => 1, 'ecx' => 1, 'cs' => 1,
  'dl' => 2, 'dx' => 2, 'edx' => 2, 'ss' => 2,
  'bl' => 3, 'bx' => 3, 'ebx' => 3, 'ds' => 3,
  'ah' => 4, 'sp' => 4, 'esp' => 4, 'fs' => 4,
  'ch' => 5, 'bp' => 5, 'ebp' => 5, 'gs' => 5,
  'dh' => 6, 'si' => 6, 'esi' => 6,
  'bh' => 7, 'di' => 7, 'edi' => 7,
};

sub RegNameToNumber {
  my $name = shift;
  return($regs->{lc($name)});
}

# Doesn't do memory adressing.
sub EncodeModRM {
  my $dst = shift;
  my $src = shift;

  return 0xc0 + $src + ($dst << 3);
}

sub EncodeEffective {
  my $shift_num = shift;
  my $reg = shift;

  return 0xc0 | ($shift_num << 3) | $reg;
}

sub Clear {
	my $reg = shift;
	my $badchars = shift;

	my @good;
	my @chars = (0x29, 0x2b, 0x31, 0x33);
	foreach(@chars)
	{
		if(index($badchars, $_) == -1)
		{
			push @good, $_;
		}
	}

	return pack("C", $good[rand(scalar @good)]) . pack("C", EncodeModRM($reg, $reg));
}

sub Mov {
	my $constant = shift;
	my $dst = RegNameToNumber(shift);
	my $badchars = shift;

	my @opcodes;
	if($constant >= 0 && $constant <= 0x7f)
	{
		push @opcodes, "\x6a" . pack("C", $constant) .  pack("C", 0x58 + $dst);
	}
	if($constant >= 0 && $constant <= 0xff)
	{
		push @opcodes, Clear($dst, $badchars) . pack("C", 0xb0 + $dst) . pack("C", $constant);
	}
	if($constant >= 0 && $constant <= 0xffff)
	{
		push @opcodes, Clear($dst, $badchars) . "\x66" . pack("C", 0xb8 + $dst) . pack("v", $constant);
	}
	push @opcodes, Clear($dst, $badchars) . pack("C", 0xb8 + $dst) . pack("V", $constant);

	my @bad = split(//, $badchars);
	for(my $index = 0; $index < scalar @opcodes; $index++)
	{
		my $failed = 0;
		foreach(@bad)
		{
			if(index($opcodes[$index], $_) != -1)
			{
				$failed = 1;
			}
		}

		if($failed == 0)
		{
			return $opcodes[$index];
		}
	}

	return $badchars; # Err, what else can we do here?
}

sub Sub {
	my $constant = shift;
	my $dst = RegNameToNumber(shift);
	my $badchars = shift;

	my @opcodes;
# XXX: Needs work. Do special encoding for eax? (One byte smaller)
	if($constant >= -0x7f && $constant <= 0x7f)
	{
		push @opcodes, Clear($dst, $badchars) . "\x83" . pack("C", EncodeEffective(5, $dst)) . pack("C", $constant); 
	}
	if($constant >= -0xffff && $constant <= 0)
	{
		push @opcodes, Clear($dst, $badchars) . "\x66\x81" . pack("C", EncodeEffective(5, $dst)) . pack("v", $constant); 
	}
	push @opcodes, Clear($dst, $badchars) . "\x81" . pack("C", EncodeEffective(5, $dst)) . pack("V", $constant); 

	my @bad = split(//, $badchars);
	for(my $index = 0; $index < scalar @opcodes; $index++)
	{
		my $failed = 0;
		foreach(@bad)
		{
			if(index($opcodes[$index], $_) != -1)
			{
				$failed = 1;
			}
		}

		if($failed == 0)
		{
			return $opcodes[$index];
		}
	}

	return $badchars; # Err, what else can we do here?
}

1;
