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
#temp for move warnings
use Pex::Text;

#
# Generate a nop sled for the appropriate architecture,
# randomizing them by default by using nop-equivalents.
#

# Nops(length, { opts });
sub Nops {
  my $defaultOpts = {
    'Arch'       => 'x86',
    'RandomNops' => 0,
#    'BadRegs'    => ['esp', 'ebp'],
  };

  my $length = shift;
  my $opts = @_ ? shift : { };
  $opts = MergeHash($opts, $defaultOpts);
  my $arch = $opts->{'Arch'};
  my $random = $opts->{'RandomNops'};
  my $badRegs = $opts->{'BadRegs'};
  my $badChars = [ split('', $opts->{'BadChars'}) ];

  # Stole from ADMutate, thanks k2
  # Bunch added and table built by spoon
  my $nops = {'x86' => [
   #[string, [ affected registers, ... ], ],
    ["\x90", [ ], ], # nop
    ["\x96", ['eax', 'esi'], ], # xchg eax,esi
    ["\x97", ['eax', 'edi'], ], # xchg eax,edi
    ["\x95", ['eax', 'ebp'], ], # xchg eax,ebp
    ["\x93", ['eax', 'ebx'], ], # xchg eax,ebx
    ["\x91", ['eax', 'ecx'], ], # xchg eax,ecx
    ["\x99", ['edx'], ], # cdq
    ["\x4d", ['ebp'], ], # dec ebp
    ["\x48", ['eax'], ], # dec eax
    ["\x47", ['edi'], ], # inc edi
    ["\x4f", ['edi'], ], # dec edi
    ["\x40", ['eax'], ], # inc eax
    ["\x41", ['ecx'], ], # inc ecx
    ["\x37", ['eax'], ], # aaa
    ["\x3f", ['eax'], ], # aas
    ["\x27", ['eax'], ], # daa
    ["\x2f", ['eax'], ], # das
    ["\x97", ['eax', 'edi'], ], # xchg eax,edi
    ["\x46", ['esi'], ], # inc esi
    ["\x4e", ['esi'], ], # dec esi
    ["\x92", ['eax', 'edx'], ], # xchg eax,edx
#flag foo fixme
#direction flag should be ok to change
    ["\xfc", [ ], ], # cld
    ["\xfd", [ ], ], # std
#carry flag should be ok to change
    ["\xf8", [ ], ], # clc
    ["\xf9", [ ], ], # stc
    ["\xf5", [ ], ], # cmc

    ["\x98", ['eax'], ], # cwde
    ["\x9f", ['eax'], ], # lahf
    ["\x4a", ['edx'], ], # dec edx
    ["\x44", ['esp'], ], # inc esp
    ["\x42", ['edx'], ], # inc edx
    ["\x43", ['ebx'], ], # inc ebx
    ["\x49", ['ecx'], ], # dec ecx
    ["\x4b", ['ebx'], ], # dec ebx
    ["\x45", ['ebp'], ], # inc ebp
    ["\x4c", ['esp'], ], # dec esp
    ["\x9b", [ ], ], # wait
    ["\x60", ['esp'], ], # pusha
    ["\x0e", ['esp'], ], # push cs
    ["\x1e", ['esp'], ], # push ds
    ["\x50", ['esp'], ], # push eax
    ["\x55", ['esp'], ], # push ebp
    ["\x53", ['esp'], ], # push ebx
    ["\x51", ['esp'], ], # push ecx
    ["\x57", ['esp'], ], # push edi
    ["\x52", ['esp'], ], # push edx
    ["\x06", ['esp'], ], # push es
    ["\x56", ['esp'], ], # push esi
    ["\x54", ['esp'], ], # push esp
    ["\x16", ['esp'], ], # push ss
    ["\x58", ['esp', 'eax'], ], # pop eax
    ["\x5d", ['esp', 'ebp'], ], # pop ebp
    ["\x5b", ['esp', 'ebx'], ], # pop ebx
    ["\x59", ['esp', 'ecx'], ], # pop ecx
    ["\x5f", ['esp', 'edi'], ], # pop edi
    ["\x5a", ['esp', 'edx'], ], # pop edx
    ["\x5e", ['esp', 'esi'], ], # pop esi
    ["\xd6", ['eax'], ], # salc
  ],};

  return undef if(!exists($nops->{$arch}));

  my @nops;
  foreach my $nop (@{$nops->{$arch}}) {
    if(!ArrayContains($nop->[1], $badRegs) && !ArrayContains($badChars, [$nop->[0]])) {
      push(@nops, $nop->[0]);
    }
    else {
#      print "Dropped.\n";
    }
  }

  return if(!@nops);

  return ($nops[0] x $length) if (! $random);
  return join ("", @nops[ map { rand @nops } ( 1 .. $length )]);
}



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


#fixme MergeHashRec
sub MergeHash {
  my $hash1 = shift || { };
  my $hash2 = shift || { };
  my %hash = %{$hash1};
  foreach (keys(%{$hash2})) {
    if(!defined($hash1->{$_})) {
      $hash{$_} = $hash2->{$_};
    }
    # recurse if both are has ref's
    elsif(ref($hash1->{$_}) eq 'HASH' && ref($hash2->{$_}) eq 'HASH') {
      $hash{$_} = MergeHash($hash1->{$_}, $hash2->{$_});
    }
  }
  return(\%hash);
}


# Weee for moving code

sub BufferC {
  print STDERR "!!! Big ass ugly warning\nThis function has been moved to Pex::Text\n";
  print STDERR "Called by " . join(' ', caller()) . "\n\n";
  return(Pex::Text::BufferC(@_));
}
sub BufferPerl {
  print STDERR "!!! Big ass ugly warning\nThis function has been moved to Pex::Text\n";
  print STDERR "Called by " . join(' ', caller()) . "\n\n";
  return(Pex::Text::BufferC(@_));
}

# I stole this.
sub FisherYates {
  my $array = shift;
  for(my $i = @{$array} - 1; $i > 1; $i--) {
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


# KeysCheck(['foo'], ['bar', 'foo'], and/or) => 1
# KeysCheck(['foo', 'bar'], ['foo'], or => 1, and => 0
# if keys1 is empty, always 1
# KeysCheck(['foo'], ['foo', '+waka'], and/or) => 0
# then if keys2 is empty, 0
sub CheckKeys {
  # Need to come up with better names for this
  my $keys1 = shift;
  my $keys2 = shift;
  my $type = @_ ? shift : 'or';

  return(1) if(!@{$keys1});
  return(0) if(!@{$keys2});

  for(my $i = 0; $i < @{$keys2}; $i++) {
    my $key = $keys2->[$i];
    my $first = substr($key, 0, 1);
    my $rest = substr($key, 1);
    if($first eq '+') {
#      print "Need $rest\n";
      return(0) if(!ArrayContains($keys1, [ $rest ]));
      splice(@{$keys2}, $i, 1, $rest);
    }
  }

#  foreach my $key (@{$keys2}) {
#    print "++ $key\n";
#  }

  if($type eq 'or') {
    return(ArrayContains($keys2, $keys1));
  }
  else {
    return(ArrayContainsAll($keys2, $keys1));
  }
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

1;
