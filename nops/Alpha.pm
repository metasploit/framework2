
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Nop::Alpha;
use strict;
use base 'Msf::Nop';
use Pex::Utils;

my $info = {
  'Name'    => 'Alpha Nop Generator',
  'Version' => '$Revision$',
  'Authors' => [ 'vlad902 <vlad902 [at] gmail.com>', ],
  'Arch'    => [ 'alpha' ],
  'Desc'    =>  'This is a very minimal Alpha nop generator',
  'Refs'    => [ ],
};

my $advanced = { };

sub new {
  my $class = shift; 
  return($class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_));
}

sub Nops {
  my $self = shift;
  my $length = shift;

  my $exploit = $self->GetVar('_Exploit');
  my $random  = $self->GetLocal('RandomNops');
  my $badChars = $exploit->PayloadBadChars;

  # Much room for future improvement :(
  # bis $31, $31, $31
  return(pack('V',0x47ff041f) x ($length / 4));
}

1;
