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
