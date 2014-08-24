#!/usr/bin/perl
use strict;
use lib 'lib';
use lib '../lib';
use Pex::Text;

die "0x01020304 length" if(!@ARGV);

my $addr = shift;
my $length = @ARGV ? shift : 200;

print join(', ', Pex::Text::PatternOffset(Pex::Text::PatternCreate($length), $addr)) . "\n";
