
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Nop::PPC;
use strict;
use base 'Msf::Nop';
use Pex::Utils;

my $info = {
  'Name'    => 'PPC Nop Generator',
  'Version' => '$Revision$',
  'Authors' => [ 'H D Moore <hdm [at] metasploit.com>', ],
  'Arch'    => [ 'ppc' ],
  'Desc'    =>  'This is a very minimal PPC nop generator',
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
  my $random  = $self->GetVar('RandomNops');
  my $badChars = $exploit->PayloadBadChars;

  # Much room for future improvement :(
  return(pack('N',0x60606060) x ($length / 4));
  
}

1;
