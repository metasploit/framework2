
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Nop::Pex;
use strict;
use base 'Msf::Nop';
use Pex::Utils;

my $info = {
  'Name'    => 'Pex Nop Generator',
  'Version' => '$Revision$',
  'Authors' => [ 'spoonm <ninjatools [at] hush.com>', ],
  'Arch'    => [ 'x86' ],
  'Desc'    =>  'The Pex library\'s x86 nop generator',
  'Refs'    => [ ],
};

my $advanced = {
  'RandomNops' => [0, 'Use random nop equivalent instructions, otherwise default to 0x90'],

};

sub new {
  my $class = shift; 
  return($class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_));
}

sub Nops {
  my $self = shift;
  my $length = shift;

  my $exploit = $self->GetVar('_Exploit');
  my $random  = $self->GetLocal('RandomNops');
  my $badRegs = $exploit->NopSaveRegs;
  my $badChars = $exploit->PayloadBadChars;

  return($self->_PexNops($length,
    {
       'Arch' => 'x86',
       'RandomNops' => $random,
       'BadRegs' => $badRegs,
       'BadChars' => $badChars,
    }
  ));
}

#
# Generate a nop sled for the appropriate architecture,
# randomizing them by default by using nop-equivalents.
#

# Nops(length, { opts });
sub _PexNops {
  my $defaultOpts = {
    'Arch'       => 'x86',
    'RandomNops' => 0,
#    'BadRegs'    => ['esp', 'ebp'],
  };
  my $self = shift;
  my $length = shift;
  my $opts = @_ ? shift : { };
  $opts = Pex::Utils::MergeHashRec($opts, $defaultOpts);
  my $arch = $opts->{'Arch'};
  my $random = $opts->{'RandomNops'};
  my $badRegs = $opts->{'BadRegs'};
  my $badChars = [ split('', $opts->{'BadChars'}) ];

  # Stole from ADMutate, thanks k2
  # Bunch added and table built by spoon
  my $nops = {'x86' => [
   #[string, [ affected registers, ... ], ],
    ["\x90", [ ], ], # nop
    ["\x97", ['eax', 'edi'], ], # xchg eax,edi
    ["\x96", ['eax', 'esi'], ], # xchg eax,esi
    ["\x95", ['eax', 'ebp'], ], # xchg eax,ebp
    ["\x93", ['eax', 'ebx'], ], # xchg eax,ebx
    ["\x92", ['eax', 'edx'], ], # xchg eax,edx
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
    ["\x46", ['esi'], ], # inc esi
    ["\x4e", ['esi'], ], # dec esi
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
    if(!Pex::Utils::ArrayContains($nop->[1], $badRegs) && !Pex::Utils::ArrayContains($badChars, [$nop->[0]])) {
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


1;
