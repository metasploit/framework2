package Msf::Payload::win32_reverse_stg_ie;
use strict;
use base 'Msf::PayloadComponent::Win32StagePayloadIE';
sub load {
  Msf::PayloadComponent::Win32StagePayloadIE->import('Msf::PayloadComponent::Win32ReverseStagerIE');
}

my $info =
{
  'Name'         => 'winreverse_stg_ie',
  'Version'      => '1.0',
  'Description'  => 'Listen for connection and spawn a shell',
  'Authors'      => [ 'H D Moore <hdm [at] metasploit.com> [Artistic License]', ],
  'UserOpts'	   =>
    {
      'IEGG' => [1, 'PATH', 'Path to InlineEgg stage'],
    },
};

sub new {
  load();
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash = $class->MergeHash($hash, {'Info' => $info});
  my $self = $class->SUPER::new($hash, @_);
  return($self);
}

1;
