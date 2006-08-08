
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
#temp for move warnings
use Pex::Text;
use FindBin qw{$RealBin};

# Returns true if array1 contains an element in array2
sub ArrayContains {
  my $array1 = shift || [ ];
  my $array2 = shift || [ ];

  foreach my $e (@{$array2}) {
    return(1) if(grep { $_ eq $e } @{$array1});
  }

  return(0);
}

# All of array2 must be in array1
sub ArrayContainsAll {
  my $array1 = shift || [ ];
  my $array2 = shift || [ ];
  foreach my $entry (@{$array2}) {
    if(!scalar(grep { $_ eq $entry } @{$array1})) {
      return(0);
    }
  }
  return(1);
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
# Rotate a 32-bit value to the right by $cnt bits (stupidly)
#

sub Ror
{
    my ($val, $cnt) = @_;
    my @bits = split(//, unpack("B32", pack("N", $val)));
    for (1 .. $cnt) { unshift @bits, pop(@bits) }
    return(unpack("N", pack("B32",  join('',@bits))));
}

#
# Rotate a 32-bit value to the left by $cnt bits (stupidly)
#

sub Rol
{
    my ($val, $cnt) = @_;
    my @bits = split(//, unpack("B32", pack("N", $val)));
    for (1 .. $cnt) { push @bits, shift(@bits) }
    return(unpack("N", pack("B32",  join('',@bits))));
}

sub MergeHashRec {
	my $hash1 = shift || { };
	my $hash2 = shift || { };
	my %hash = %{$hash1};
	
	foreach my $hk (keys(%{ $hash2 })) {
		
		# Merge empty values with new ones
		if (! defined($hash1->{$hk})) {
			$hash{$hk} = $hash2->{$hk};
		}
		# Handle hash -> hash merges
		elsif (ref($hash1->{$hk}) eq 'HASH' && ref($hash2->{$hk}) eq 'HASH') {
			$hash{$hk} = MergeHashRec($hash1->{$hk}, $hash2->{$hk});
		}
		# Handle array -> array merges
		elsif (ref($hash1->{$hk}) eq 'ARRAY' && ref($hash2->{$hk}) eq 'ARRAY') {

			# Initial value is set to hash1
			$hash{$hk} = $hash1->{$hk};
			
			# Attempt to preserve array order
			my %uvals = ();
			map { $uvals{$_}++ } @{ $hash{$hk} };
			
			# Add unique items in hash2 to the stack
			foreach my $val ( @{ $hash2->{$hk} } ) {
				if (! $uvals{$val}) {
					push @{ $hash{$hk} }, $val;
				}
			}
		}
	}
	return(\%hash);
}

# I stole this.
sub FisherYates {
  my $array = shift;
  for(my $i = @{$array} - 1; $i > 0; $i--) {
    my $j = int(rand($i + 1));
    next if($i == $j);
    @$array[$i, $j] = @$array[$j, $i];
  }
}

sub WriteFile {
  my $filename = shift;
  my $data = shift;
  my $append = @_ ? shift : 0;
  my $prefix = $append ? '>>' : '>';

  open(OUTFILE, $prefix . $filename) or return;
  print OUTFILE $data;
  close(OUTFILE);
}
sub ReadFile {
  my $filename = shift;
  open(INFILE, '<' . $filename) or return;
  local $/;
  my $data = <INFILE>;
  close(INFILE);
  return($data);
}


# CheckKeys(['foo'], ['bar', 'foo'], and/or) => 1
# CheckKeys(['foo', 'bar'], ['foo'], or => 1, and => 0
# if keys1 is empty, always 1
# CheckKeys(['foo'], ['foo', '+waka'], and/or) => 0
# then if keys2 is empty, 0
sub CheckKeys {
  # Need to come up with better names for this
  my $keys1 = shift;
  my $keys2 = shift;
  my $type = @_ ? shift : 'or';

  return(1) if(!@{$keys1});
  return(0) if(!@{$keys2});

  my @keys2 = @{$keys2};

  for(my $i = 0; $i < @keys2; $i++) {
    my $key = $keys2[$i];
    my $first = substr($key, 0, 1);
    my $rest = substr($key, 1);
    if($first eq '+') {
      return(0) if(!ArrayContains($keys1, [ $rest ]));
      splice(@keys2, $i, 1, $rest);
    }
  }

  # print "[ checkkeys ]\n";
  # print "keys1: ".join(" ", @{ $keys1 })."\n";
  # print "keys2: ".join(" ", @keys2)."\n";
  
  return ($type eq 'or') ?
         ArrayContains(\@keys2, $keys1) :
		 ArrayContainsAll(\@keys2, $keys1);
}

sub ParseKeys {
  my $defaults = shift;
  my $keys = shift;

  my %defaults;
  my %user;
  foreach my $def (@{$defaults}) {
    $defaults{$def} = 1;
  }

  foreach my $key (@{$keys}) {
    my $first = substr($key, 0, 1);
    my $rest = substr($key, 1);
    if($first eq '-') {
      delete($defaults{$rest});
    }
    elsif($first eq '+') {
      $defaults{$rest} = 1;
    }
    else {
      $user{$key} = 1;
    }
  }

  return(keys(%user)) if(keys(%user));
  return(keys(%defaults));
}


# Create a UDP socket to a random internet host and use it to 
# determine our local IP address, without actually sending data
sub SourceIP {
	my $dst = @_ ? shift() : '4.3.2.1';
    my $res = '127.0.0.1';
    my $s = IO::Socket::INET->new(PeerAddr => $dst, PeerPort => 53, Proto => 'udp') 
    || return $res;    
    $res = $s->sockhost;   
    $s->close();
    undef($s);
    return $res;
}

sub DataTree {
  my $data = shift;
  return(_DataTreeDispatch($data, 0) . "\n");
}

sub _DataTreeDispatch {
  my $data = shift;
  my $indent = shift;
  if(ref($data) eq '') {
    return(_DataTreeScalar($data, $indent));
  }
  elsif(ref($data) eq 'ARRAY') {
    return(_DataTreeArray($data, $indent));
  }
  elsif(ref($data) eq 'HASH') {
    return(_DataTreeHash($data, $indent));
  }
}

sub _DataTreeScalar {
  my $scalar = shift;
  my $indent = shift;
  return(' ' x $indent . $scalar);
}
sub _DataTreeArray {
  my $array = shift;
  my $indent = shift;
  my $text;
  $text .= ' ' x $indent;
  $text .= "[\n";
  foreach my $element (@{$array}) {
    $text .= _DataTreeDispatch($element, $indent + 1) . ",\n";
  }

  $text .= ' ' x $indent;
  $text .= "]";
  return($text);
}
sub _DataTreeHash {
  my $hash = shift;
  my $indent = shift;
  my $text;
  $text .= ' ' x $indent;
  $text .= "{\n";
  foreach my $key (keys(%{$hash})) {
    $text .= ' ' x ($indent + 1);
    $text .= "$key =>\n" . _DataTreeDispatch($hash->{$key}, $indent + 1) . ",\n";
  }

  $text .= ' ' x $indent;
  $text .= "}";
  return($text);
}

sub Rev2Ver {
  my $ver = shift;
  my ($rev) = $ver =~ m/\$Revisio.:\s+([^\$]+)/;
  return ($rev) ? $rev : '0.0';  
}


# fmt string generator using %hn, seems to work fine against x86 linux
# and solaris sparc, takes where and what (obvious), offset to the dword
# of controlled (beginning of fmt usually), and before which is the number
# of characters printed before our controlled part of the fmt string
# Some ideas taken from Pappy & Zorgon

sub FormatOverwrite {
  my %opts = @_;
  $opts{'pack'} = 'V' if(!exists($opts{'pack'}));
  $opts{'offset'} = 0 if(!exists($opts{'offset'}));
  $opts{'before'} = 0 if(!exists($opts{'before'}));
  my $pack   = $opts{'pack'};
  my $what   = $opts{'what'};
  my $where  = $opts{'where'};
  my $offset = $opts{'offset'};
  my $before = $opts{'before'};
  my $string;


  # For big/little endian difference you could also swap the order
  # of the where and where + 2, but I just do what change because
  # um, yeah
  $string .= pack($pack, $where) . pack($pack, $where + 2);
  my $first = $pack eq 'N' ? 
    ($what >> 16)    - $before - 8 : # Big endian write the high 16
    ($what & 0xffff) - $before - 8;  # Little endian write the low 16

  while($first < 8) {
    $first += 0x10000;
  }
  $string .= '%.' . $first . 'x%' . $offset . '$hn';
  my $second = $pack eq 'N' ?
    ($what & 0xffff) - $first - 8 : # And so on
    ($what >> 16)    - $first - 8;

#  print STDERR "Second before $second\n";
  while($second < 8) {
    $second += 0x10000;
  }
#  print STDERR "Second after $second\n";
  $string .= '%.' . $second . 'x%' . ($offset + 1) . '$hn';

  return($string);
}

# Dword (32-bit) add
# Add some perl numbers, dropping the overflow.
sub DwordAdd {
  my $num1 = shift;
  my $num2 = shift;
  return(($num1 + $num2) % 4294967296);
}

# Create a Windows executable with the selected contents
sub CreateWin32PE {
	my $bin = shift();
	my $com = shift() || '';
	my $pedata;
	local $/;
	
	if(! open(TMP, "<$RealBin/data/msfpayload/template.exe")) {
		return(0);
	}

	$pedata = <TMP>;
	close (TMP);
	
	# Comments are limited to 512 bytes
	# Payloads are limited to 8192 bytes
	
	my $bin_off = index($pedata, 'PAYLOAD:');
	if ($bin_off == -1) {
		return(0);
	}
	
	# Replace the stub data with the actual payload
	substr($pedata, $bin_off, 8192, pack('a8192', $bin));

	my $com_off = index($pedata, 'COMMENT:');
	if ($com_off == -1) {
		return(0);
	}

	# Replace the stub comment with payload information
	substr($pedata, $com_off, 512, pack('a512', $com));
	
	return($pedata);
}

# Escape data into javascript array
sub JSUnescape {
	my $data = shift;
	my $mode = shift() || 'LE';
	my $code = '';
	
	# Encode the shellcode via %u sequences for JS's unescape() function
	my $idx = 0;
	
	# Pad to an even number of bytes
	if (length($data) % 2 != 0) {
		$data .= substr($data, -1, 1);
	}
	
	while ($idx < length($data) - 1) {
		my $c1 = ord(substr($data, $idx, 1));
		my $c2 = ord(substr($data, $idx+1, 1));	
		if ($mode eq 'LE') {
			$code .= sprintf('%%u%.2x%.2x', $c2, $c1);	
		} else {
			$code .= sprintf('%%u%.2x%.2x', $c1, $c2);	
		}
		$idx += 2;
	}
	
	return $code;
}

1;
