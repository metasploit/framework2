package Msf::Encoder::PexFnstenv;
use strict;
use base 'Msf::Encoder';
use Pex::Encoder;

my $info = {
  'Name'  => 'Pex Fnstenv Double Word Xor Encoder',
  'Version'  => '1.0',
  'Author'  => 'spoonm <ninjatools [at] hush.com> H D Mooore <hdm[at]metasploit.com> [Artistic License]',
  'Arch'  => [ 'x86' ],
  'OS'    => [ ],
  'Desc'  =>  'Pex Double Word Xor Encoder',
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
  return(Pex::Encoder::EncodeFnstenv($rawshell, $badChars));
}

1;
