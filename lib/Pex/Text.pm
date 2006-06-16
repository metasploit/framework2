
###############

##
#         Name: Text.pm
#       Author: spoonm <ninjatools [at] hush.com>
#       Author: We steal da codez, more credits inline
#      Version: $Revision$
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##


package Pex::Text;
use strict;


# Pulled from MIME-Base64-2.13
# Contributed to MIME::Base64 by Paul Szabo <psz@maths.usyd.edu.au>
# Hacked on to remove use integer, and general cleanup things, and
# hopefully some speed optimization (not that it matters)  -spoon
sub Base64Encode {
  my $data = shift;
  my $eol = @_ ? shift : "\n";

  my $res = pack('u', $data);
  # Remove first character of each line, remove newlines
  $res =~ s/^.//mg;
  $res =~ s/\n//g;

  $res =~ tr|` -_|AA-Za-z0-9+/|;               # `# help emacs
  # fix padding at the end
  my $padding = (3 - length($data)) % 3;
  substr($res, -1 * $padding,  $padding, '=' x $padding);
  # break encoded string into lines of no more than 76 characters each
  if (length $eol) {
    $res =~ s/(.{1,76})/$1$eol/g;
  }
  return $res;
}

sub Base64Decode {
  my $str = shift;
  $str =~ tr|A-Za-z0-9+=/||cd;            # remove non-base64 chars
  if (length($str) % 4) {
    return;
  }
  $str =~ s/=+$//;                        # remove padding
  $str =~ tr|A-Za-z0-9+/| -_|;            # convert to uuencoded format

  ## I guess this could be written as
  #return unpack("u", join('', map( chr(32 + int(length($_)*3/4)) . $_,
  #                   $str =~ /(.{1,60})/gs) ) );
  ## but I do not like that...
  my $uustr = '';
  my ($i, $l);
  $l = length($str) - 60;
  for ($i = 0; $i <= $l; $i += 60) {
    $uustr .= 'M' . substr($str, $i, 60);
  }
  $str = substr($str, $i);
  # and any leftover chars
  if ($str ne '') {
    $uustr .= chr(32 + length($str)*3/4) . $str;
  }
  return unpack ('u', $uustr);
}

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
  my $size = int(shift());
  my $string;
  my $start = 33;
  my $stop = 126;

  for(my $i = 0; $i < $size; $i++) {
    $string .= chr(int(rand($stop - $start)) + $start);
  }

  return($string);
}

sub AlphaNumText {
  my $size = int(shift());
  my @chars = @_ ? split('', shift) : ('A' .. 'Z', 'a' .. 'z', '0' .. '9');

  my $data;
  while($size--) {
    $data .= $chars[int(rand(@chars))];
  }
  return($data);
}

sub LowerCaseText {
  my $size = int(shift());
  my @chars = @_ ? split('', shift) : ('a' .. 'z');

  my $data;
  while($size--) {
    $data .= $chars[int(rand(@chars))];
  }
  return($data);
}

sub UpperCaseText {
  my $size = int(shift());
  my @chars = @_ ? split('', shift) : ('A' .. 'Z');

  my $data;
  while($size--) {
    $data .= $chars[int(rand(@chars))];
  }
  return($data);
}

# inverse a string of chars, include all the bytes it doesn't include...
# inverse of 0x00 .. 0x80 = 0x81 .. 0xff, etc
sub InverseChars {
  my $badChars = shift;
  my $chars;
  foreach my $c (0x00 .. 0xff) {
    $c = chr($c);
    if(index($badChars, $c) == -1) {
      $chars .= $c;
    }
  }
  return($chars);
}

# size, BadCharsString...
sub RandomChars {
  my $size = int(shift());
  my $badChars = shift;
  my @chars = split('', InverseChars($badChars));
  my $data;

  while($size--) {
    $data .= $chars[int(rand(@chars))];
  }

  return($data);
}

sub RandomData {
  my $size = int(shift());
  my $string;

  for(my $i = 0; $i < $size; $i++) {
    $string .= chr(int(rand(256)));
  }

  return($string);
}


sub BadCharCheck {
  return(BadCharIndex(@_) == -1 ? 0 : 1);
}

sub BadCharIndex {
  my @indexes = BadCharIndexes(@_);
  return(-1) if(!@indexes);
  return($indexes[0]);
}

sub BadCharIndexes {
  my $badChars = @_ ? shift : return;
  my $string = @_ ? shift : return;
  my @indexes;

  my $i = 0;
  foreach (split('', $string)) {
    if(index($badChars, $_) != -1) {
      push(@indexes, $i);
    }
    $i++;
  }
  return(@indexes);
}

# This is ugly, it sucks, just ignore it
sub Freeform {
  my $data = shift;
  $data =~ s/^\s+//g;
  $data =~ s/\s+$//g;
  $data =~ s/^[ \t]+//gm;
  $data =~ s/[ \t]+$//gm;
  $data =~ s/(\n+)/length($1) == 1 ? " " : "\n" x length($1)/eg;
  return($data);
}


sub PatternCreate {
    my ($length) = @_;
    my ($X, $Y, $Z);
    my $res;

    while (1)
    {
        for my $X ("A" .. "Z") { for my $Y ("a" .. "z") { for my $Z (0 .. 9) {
           $res .= $X;
           return $res if length($res) >= $length;

           $res .= $Y;
           return $res if length($res) >= $length;

           $res .= $Z;
           return $res if length($res) >= $length;
        }}}
    }
}

sub PatternOffset {
     my $pattern = shift;
     my $address = shift;
     my $endian = @_ ? shift() : 'V';
     my @results;
     my ($idx, $lst) = (0,0);

     $address = pack($endian, hex($address));
     $idx = index($pattern, $address, $lst);

     while ($idx > 0)
     {
          push @results, $idx;
          $lst = $idx + 1;
          $idx = index($pattern, $address, $lst);
     }
     return @results;
}

sub URLEncode {
	my $data = shift;
	my $res;

	foreach my $c (unpack('C*', $data)) {
		if (
			($c >= 0x30 && $c <= 0x39) ||
			($c >= 0x41 && $c <= 0x5A) ||
			($c >= 0x61 && $c <= 0x7A)
		  ) {
			$res .= chr($c);
		} else {
			$res .= sprintf("%%%.2x", $c);
		}
	}
	return $res;
}

1;
