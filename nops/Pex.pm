package Msf::Nop::Pex;
use strict;
use base 'Msf::Nop';
use Pex::Utils;

my $info = {
  'Name'    => 'Pex Nop Generator',
  'Version' => '1.0',
  'Author'  => 'H D Mooore <hdm[at]metasploit.com> [Artistic License]',
  'Arch'    => [ 'x86' ],
  'Desc'    =>  'Pex Nop Generator',
  'Refs'    => [ ],
};

my $advanced = {
  'Random' => [0, 'Use random nop equivalent instructions, otherwise default to 0x90'],
};

sub new {
  my $class = shift; 
  return($class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_));
}

sub Nops {
  my $self = shift;
  my $length = shift;

  return(Pex::Utils::Nops($length, 'x86', $self->GetLocal('Random')));
}

1;
