package Msf::Payload::cmd_generic;
use strict;
use base 'Msf::CommandPayload';

my $info =
{
    Name         => 'cmd_generic',
    Version      => '1.0',
    Description  => 'Run a specific command on the remote system',
    Author       => 'H D Mooore <hdm[at]metasploit.com> [Artistic License]',
    Arch         => [  ],
    Priv         => 0,
    OS           => [ ],
    Keys         => ['cmd'], 
    Multistage   => 0,
    Type         => 'none',
    Size         => '',
    UserOpts     =>
        {
            'CMD' => [1, 'DATA', 'The command to execute'],
        },
        
    CommandPayload => "[>CMD<]",
};

sub new {
    my $class = shift;
    my $self = $class->SUPER::new({'Info' => $info}, @_);
    return($self);
}
