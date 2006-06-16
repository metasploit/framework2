#!/usr/bin/perl
use strict;

die(qq{
Spitcode, stupid little utility for extracting things in double quotes, for
example char strings in c/perl code (like shellcode).  Will just read this
in on stdin, and write it out on stdout.

-n will supress printing a newline afterwards.

}) if($ARGV[0] eq '-h');

my $foo;

while(<STDIN>) {
  if(/"(.*?)"/) {
    $foo .= $1;
  }
}

print $foo;
print "\n" if($ARGV[0] ne '-n');
