#!/usr/bin/perl
###############

##
#         Name: Utils.pm
#       Author: H D Moore <hdm [at] metasploit.com>
#       Author: spoonm <ninjatools [at] hush.com>
#      Version: $Revision$
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##


package Pex::Utils;
use strict;

#
# Generate a nop sled for the appropriate architecture,
# randomizing them by default by using nop-equivalents.
#

sub Nops {
  my $length = shift;
  my $arch = @_ ? shift : 'x86'; # default to x86
  my $random = @_ ? shift : 1;   # default to random

  # Stole from ADMutate, thanks k2
  my @nops;
  my $nops =
  {
    "x86" => "\x90\x96\x97\x95\x93\x91\x99\x4d\x48\x47\x4f\x40\x41\x37\x3f\x97".
             "\x46\x4e\xf8\x92\xfc\x98\x27\x2f\x9f\xf9\x4a\x44\x42\x43\x49\x4b".
             "\xf5\x45\x4c",
  };

  return undef if ! exists($nops->{$arch});
  @nops = split('', $nops->{$arch});
  
  return ($nops[0] x $length) if (! $random);
  return join ("", @nops[ map { rand @nops } ( 1 .. $length )]);
}


#
# This returns a hash value that is usable by the win32
# api loader shellcode. The win32 payloads call this to
# do runtime configuration (change function calls around)
#

sub RorHash
{
    my $name = shift;
    my $hash = 0;
    
    foreach my $c (split(//, $name))
    {
        $hash = Ror($hash, 13);
        $hash += ord($c);
    }
    return $hash;
}


#
# Rotate a 32-bit value to the right by $cnt bits
#

sub Ror
{
    my ($val, $cnt) = @_;
    my @bits = split(//, unpack("B32", pack("N", $val)));
    for (1 .. $cnt) { unshift @bits, pop(@bits) }
    return(unpack("N", pack("B32",  join('',@bits))));
}

#
# Rotate a 32-bit value to the left by $cnt bits
#

sub Rol
{
    my ($val, $cnt) = @_;
    my @bits = split(//, unpack("B32", pack("N", $val)));
    for (1 .. $cnt) { push @bits, shift(@bits) }
    return(unpack("N", pack("B32",  join('',@bits))));
}


#
# Data formatting routines
#


sub BufferPerl
{
    my ($data, $width) = @_;
    my ($res, $count);

    if (! $data) { return }
    if (! $width) { $width = 16 }
    
    $res = '"';
    
    $count = 0;
    foreach my $char (split(//, $data))
    {
        if ($count == $width)
        {
            $res .= '".' . "\n" . '"';
            $count = 0;
        }
        $res .= sprintf("\\x%.2x", ord($char));
        $count++;
    }
    if ($count) { $res .= '";' . "\n"; }
    return $res;
}

sub BufferC
{
    my ($data, $width) = @_;
    my $res = BufferPerl($data, $width);
    if (! $res) { return }
    
    $res =~ s/\.//g;
    return $res;
}

sub PadBuffer {
  my $string = shift;
  my $length = shift;
  my $pad = @_ ? shift : "\x00";

  return if($length <= 0);

  return(substr($string, 0, $length) . ($pad x ($length - length($string))));
}

sub CharsInBuffer {
    my $buff = shift;
    my @char = split(//, shift());
    for (@char) { return(1) if index($buff, $_) != -1 }
    return(0);
}

sub EnglishText {
  my $size = shift;
  my $string;
  my $start = 33;
  my $stop = 126;

  for(my $i = 0; $i < $size; $i++) {
    $string .= chr(int(rand($stop - $start)) + $start);
  }

  return($string);
}

1;
