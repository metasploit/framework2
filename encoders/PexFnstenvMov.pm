package Msf::Encoder::PexFnstenvMov;
use strict;
use base 'Msf::Encoder';
use Pex::Encoder;
my $advanced = {
  'PexDebug' => [0, 'Sets the Pex Debugging level (zero is no output)'],
};

my $info = {
  'Name'  => 'Pex Variable Length Fnstenv/mov Double Word Xor Encoder',
  'Version'  => '1.0',
  'Author'  => 'spoonm <ninjatools [at] hush.com> [Artistic License]',
  'Arch'  => [ 'x86' ],
  'OS'    => [ ],
  'Desc'  =>  'Pex Double Word Xor Encoder',
  'Refs'  => [ ],
};

sub new {
  my $class = shift; 
  return($class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_));
}

sub EncodePayload {
  my $self = shift;
  my $rawshell = shift;
  my $badChars = shift;
  return(Pex::Encoder::Encode('x86', 'DWord Xor', 'Fnstenv Mov', $rawshell, $badChars, $self->GetLocal('PexDebug')));
}

1;
