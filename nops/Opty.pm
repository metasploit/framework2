
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Nop::Opty;
use strict;
use base 'Msf::Nop::OptyNop';
use Pex::Utils;

my $info = {
  'Name'    => 'Optyx uber nop generator',
  'Version' => '$Revision$',
  'Authors' => [ 'spoonm <ninjatools [at] hush.com>', ],
  'Arch'    => [ 'x86' ],
  'Desc'    => 'Variable instruction length nop generator',
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

  $self->_BadChars($badChars);

  return($self->_GenerateSlide($length));
}

sub _BadChars {
  my $self = shift;
  $self->{'_BadChars'} = shift if(@_);
  return($self->{'_BadChars'});
}

1;
