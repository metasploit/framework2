
###############

##
#         Name: Encoder.pm
#       Author: spoonm <ninjatools [at] hush.com>
#      Version: $Revision$
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Pex::Encoding::XorWord;
use strict;
use Pex::Encoder;
use Pex::Text;

#
# These routines take a buffer and xor encodes it with the given key
# value. The data is aligned to keysize blocks and padded with xor'd
# null values (to prevent pad ^ key problems)
#

# Word (2-byte) Xor Encoding Routine
# xor (which is the key) is passed as a perl number, unpack that shit with V yo
sub Encode {
  my $self = shift;
  my $xor = shift;
  my $buffer = shift;

  my $data;

  for(my $c = 0; $c < length($buffer); $c += 2) {
    my $chunk = substr($buffer, $c, 2);
    $chunk .= "\x00" x (2 - length($chunk));
    $chunk = unpack('v', $chunk) ^ $xor;
    $data .= pack('v', $chunk);
  }

  return($data);
}

sub KeyScan {
  my $self = shift;
  print "No KeyScan for word xor implemented!\n";
  return;
}

1;
