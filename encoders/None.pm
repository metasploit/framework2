package Msf::Encoder::None;
use strict;
use base 'Msf::Encoder';

my $info = {
  'Name'  => 'None Encoder',
  'Version'  => '1.0',
  'Author'  => 'spoonm <spoonm[at]ghettohackers.net> [Artistic License]',
  'Arch'  => [ 'x86' ],
  'OS'    => [ ],
  'Desc'  =>  'This encoder does not encode',
  'Refs'  => [ ],
};

sub new {
  my $class = shift; 
  return($class->SUPER::new({'Info' => $info}, @_));
}

sub EncodePayload {
  my $self = shift;
  my $rawshell = shift;
  my $badChars = shift;
  return($rawshell);
}

1;
