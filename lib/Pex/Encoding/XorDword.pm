
###############

##
#         Name: XorDword.pm
#       Author: spoonm <ninjatools [at] hush.com>
#      Version: $Revision$
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Pex::Encoding::XorDword;
use strict;
use Pex::Encoder;
use Pex::Text;

#sub new {
#  my $class = shift;
#  my $self = bless({ }, $class);
#  return($self);
#}

#
# These routines take a buffer and xor encodes it with the given key
# value. The data is aligned to keysize blocks and padded with xor'd
# null values (to prevent pad ^ key problems)
#

# Dword Xor Encoding Routine
# xor (which is the key) is passed as a perl number, unpack that shit with V yo
sub Encode {
  my $self = shift;
  my $xor = shift;
  my $buffer = shift;

  my $data;

  for(my $c = 0; $c < length($buffer); $c += 4) {
    my $chunk = substr($buffer, $c, 4);
    $chunk .= "\x00" x (4 - length($chunk));
    $chunk = unpack('V', $chunk) ^ $xor;
    $data .= pack('V', $chunk);
  }

  return($data);
}

sub KeyScan {
  my $self = shift;

  my $ref = $self->_KeyScanBytes(@_);
  return if(!defined($ref));
  my @bytes = @{$ref};
  return if(@bytes != 4);
  return(unpack('V', pack('C4', @bytes)));
}
  

# Straight up Xor Dword KeyScan yo
sub _KeyScanBytes {
  my $self = shift;
  my $data = shift;
  my $badChars = shift;

  my $badKeys;

  $badKeys = $self->_FindBadKeys($data, $badChars);

  my($keys, $r) = $self->_FindKey($badKeys, $badChars);
  return if(!defined($keys) || @{$keys} != 4);

  return($keys);
}

# <joke>
# THIS ALGORITHM IS PATEND-PENDING BY JULIANO[at]COREST.COM AND USED UNDER LICENSE
# ATTEMPTS TO REVERSE ENGINEER THIS CODE WILL BE PROSECUTED UNDER THE DMCA
# </joke>

# <not-joke>
# I will eat your soul.
# </not-joke>

# I added some randomness, seems to work.  The idea is that you won't get the
# same key for the same payload like you would before. -spn

sub _FindBadKeys {
  my $self = shift;
  my $data = shift;
  my $badChars = shift;

  my @dataFreq;
  my @badKeys;
  my %badChars;

  my $i = 0;
  foreach my $c (split('', $data)) {
    $dataFreq[$i++ % 4]->{ord($c)}++;
  }

  foreach my $c (split('', $badChars)) {
    for my $i (0 .. 3) {
      foreach my $d (keys(%{$dataFreq[$i]})) {
        $badKeys[$i]->{ord($c) ^ $d}++;
      }
    }
  }
  return(\@badKeys);
}

# This will attempt to find a valid xor key based on the badKeys and badChars
# It will return an array of the key values, and also will return a array of
# the starting points it tried to find the key at (so you can avoid rechecking
# keys that have already been checked).
# will return undef if it can't find a key
sub _FindKey {
  my $self = shift;
  my $badKeys = shift;
  my $badChars = shift;

  my @keys;
  my @r;

LOOP:
  for my $d (0 .. 3) {
    $r[$d] = int(rand(254));
    for my $c ($r[$d] .. $r[$d] + 254) {
      $c = ($c % 255) + 1;
      next if($badKeys->[$d]->{$c} || index($badChars, $c) != -1);
      $keys[$d] = $c;
      next LOOP;
    }
    # shit.
#    print "Damn on $d\n";
    return;
  }

#  print "1 SUCCESS! " . join('-', @keys) . "\n";
  return(\@keys, \@r);
}


sub _Check {
  my $self = shift;
  my $key = shift;
  my $data = shift;
  my $badChars = shift;
  return(Pex::Text::BadCharIndex($badChars, $self->Encode($key, $data)));
}

sub _UnitTest {
  my $self = shift;
#  my $self = $self->new;

  my $string = "\x00\x01\x02AABBCCDD";
  my $badChars = "\x00A";
  my $key = $self->KeyScan($string, $badChars);
  if(!defined($key)) {
    print "KeyScan failed!\n";
    return;
  }

  printf("Found key 0x%08x\n", $key);

  my $enc = $self->Encode($key, $string);

  if(!defined($enc)) {
    print "Encoder failed!\n";
    return;
  }

  print "Encoded data:\n";
  print Pex::Text::BufferC($enc);

  if(Pex::Text::BadCharCheck($enc, $badChars)) {
    print "Bad chars in encoded data!\n";
  }

  print "Test complete\n";

}

1;
