package Msf::Nop::Pex;
use strict;
use base 'Msf::Nop';
use Pex::Utils;

my $info = {
  'Name'    => 'Pex Nop Generator',
  'Version' => '1.0',
  'Authors' => [ 'spoonm <ninjatools [at] hush.com> [Artistic License]', ],
  'Arch'    => [ 'x86' ],
  'Desc'    =>  'Pex Nop Generator',
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
  my $badRegs = $exploit->NopBadRegs;
  my $badChars = $exploit->PayloadBadChars;

  return(Pex::Utils::Nops($length,
    {
       'Arch' => 'x86',
       'RandomNops' => $random,
       'BadRegs' => $badRegs,
       'BadChars' => $badChars,
    }
  ));
}

1;
