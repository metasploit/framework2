
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors fields below. In the
# case of an Unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors fields below. In the
# case of an Unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##


package Msf::Payload::cmd_generic;
use strict;
use base 'Msf::PayloadComponent::CommandPayload';
sub load {
  Msf::PayloadComponent::CommandPayload->import('Msf::PayloadComponent::NoConnection');
}

my $info =
{
  'Name'         => 'cmd_generic',
  'Version'      => '$Revision$',
  'Description'  => 'Run a specific command on the remote system',
  'Authors'      => [ 'H D Moore <hdm [at] metasploit.com> [Artistic License]', ],
  'Arch'         => [  ],
  'Priv'         => 0,
  'OS'           => [ ], 
  'UserOpts'     =>
    {
      'CMD' => [1, 'DATA', 'The command to execute'],
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

sub CommandString {
  my $self = shift;
  return($self->GetVar('CMD'));
}

1;
