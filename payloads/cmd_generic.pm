
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::cmd_generic;
use strict;
use base 'Msf::PayloadComponent::CommandPayload';
sub _Load {
  Msf::PayloadComponent::CommandPayload->_Import('Msf::PayloadComponent::NoConnection');
  __PACKAGE__->SUPER::_Load();
}

my $info =
{
  'Name'         => 'Arbitrary Command',
  'Version'      => '$Revision$',
  'Description'  => 'Run a specific command on the remote system',
  'Authors'      => [ 'H D Moore <hdm [at] metasploit.com>', ],
  'Priv'         => 0,
  'UserOpts'     =>
    {
      'CMD' => [1, 'DATA', 'The command to execute'],
    },
};

sub new {
  _Load();
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash = $class->MergeHashRec($hash, {'Info' => $info});
  my $self = $class->SUPER::new($hash, @_);
  return($self);
}

sub CommandString {
  my $self = shift;
  return($self->GetVar('CMD'));
}

1;
