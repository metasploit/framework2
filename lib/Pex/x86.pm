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

sub jmpShort {
  my $dist = number(shift, -2);
  return("\xeb" . numberPackLSB($dist));
}

sub number {
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

sub numberPack8 {
  my $number = shift;
  $number = number($number);
  return(numberPackLSB($number));
}
sub numberPack16 {
  my $number = shift;
  $number = number($number);
  return(numberPackLSW($number));
}
sub numberPack32 {
  my $number = shift;
  $number = number($number);
  return(numberPack($number));
}

sub numberPackLSB {
  my $number = shift;
  return(substr(numberPack($number), 0, 1));
}

sub numberPackLSW {
  my $number = shift;
  return(substr(numberPack($number), 0, 2));
}

sub numberPack {
  my $number = shift;
  return(pack('V', $number));
}

sub numberUnpack {
  my $packed = shift;
#  print "Length: " . length($packed) . "\n";
  $packed .= "\x00" x (4 - length($packed));
#  print "Length: " . length($packed) . "\n";
  return(unpack('V', $packed));
}
1;
