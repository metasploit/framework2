#!/usr/bin/perl
###############

##
#         Name: x86.pm
#       Author: spoonm <ninjatools [at] hush.com>
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

sub RelNumber {
  my $number = shift;
  my $delta = @_ ? shift : 0;

  if(substr($number, 0, 2) eq '$+') {
    $number = substr($number, 2);
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
  'al' => 0, 'ax' => 0, 'eax' => 0,
  'cl' => 1, 'cx' => 1, 'ecx' => 1,
  'dl' => 2, 'dx' => 2, 'edx' => 2,
  'bl' => 3, 'bx' => 3, 'ebx' => 3,
  'ah' => 4, 'sp' => 4, 'esp' => 4,
  'ch' => 5, 'bp' => 5, 'ebp' => 5,
  'dh' => 6, 'si' => 6, 'esi' => 6,
  'bh' => 7, 'di' => 7, 'edi' => 7,
};

sub RegNameToNumber {
  my $name = shift;
  return($regs->{lc($name)});
}

1;
