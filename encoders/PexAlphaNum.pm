package Msf::Encoder::PexAlphaNum;
use strict;
use base 'Msf::Encoder';
use Pex::Encoder;

my $info = {
  'Name'  => 'Pex Alphanumeric Encoder',
  'Version'  => '1.0',
  'Author'  => 'H D Moore <hdm [at] metasploit.com> [Artistic License]',
  'Arch'  => [ 'x86' ],
  'OS'    => [ ],
  'Desc'  =>  "Skylined's alphanumeric encoder ported to perl",
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
  return(Pex::Encoder::EncodeAlphaNum($rawshell, $badChars, $self->GetVar("GETPCTYPE")));
}

1;
