#!/usr/bin/perl
package Msf::Nop::OptyNop;
use strict;
use base 'Msf::Nop';
use Pex::Text;

# This is OptyNop.
# The code is a port of optyx's nop generator.
# I've changed things a bit, like how prefixes are done, and added support
# for jmps, worked on the tables a bit, etc...

# thanks much to scrippie for input and ideas...

# It is much more likely to reach a register-less instruction, or one whose
# registers are in it's first code byte (ie codeLen == 1) and have it work.
# So this will throw off our spread a bit, because these will pretty much
# always work, but more complicated instructions have a less likely chance
# of working, but we want those instructions!
# This is a synthetic weight to try to get more of these... the higher it
# goes the more complicated instructions you should get, but also slower!
my $synWeight = 3;

# Make sure to tune w/ bigger sleds, small sleds are hard to get complex
# instructions for anyway...

# Set debug = 2 for a auto-adjusting synWeight, just an experiment

# Print a . for all simple (codeLen == 1/SetReg) and print a + for all the
# more complicated instructions.  Nice to use to tune synWeight.
my $debug = 2;

my $none  = 0;
my $reg1  = 1;
my $reg2  = 2;

my $eax = 0;
my $ecx = 1;
my $edx = 2;
my $ebx = 3;
my $esp = 4;
my $ebp = 5;
my $esi = 6;
my $edi = 7;
my $sreg1 = 8;
my $sreg2 = 9;
my $sreg1b = 10;
my $sreg2b = 11;

# you can do pretty much aribitrary \x66 and \x67 injection before any
# instruction, including rotating both....
# deserves more testing....
# spoonm@chibi:~/msfcvs/framework$ echo -ne "\x66\x67\x66\x67\x99\xcc" | ndisasm -u -
# 00000000  6667666799        a16 cwd
# 00000005  CC                int3
# spoonm@chibi:~/msfcvs/framework$ echo -ne "\x66\x67\x66\x67\x99\xcc" | ./testybitch
# read: 6
# Trace/breakpoint trap
# according to the intel manual, things like above have undefined results.

# someday this will all be leeter, but it's not so bad for now :)

# This is a blacklist entry, it means you CANNOT do it if you have this flag
my $osize = $reg2 << 1; # \x66
my $asize = $osize << 1; # \x67

# segment overrides also seem unsafe...
#my $fsseg = $asize << 1; # \x64
#my $dsseg = $fsseg << 1; # \x3e
#my $csseg = $dsseg << 1; # \x2e
# no rep, seems to be fairly unsafe.
#my $rep = $csseg << 1; # \xf3

# is it a prefix?
my $prefix = $asize << 1;

my $table = [

  # The convention of this table, if there is only 1 register in the instruction
  # then that is reg1, if there is two registers, the lowest 3 bits is reg1, and
  # the higher 3 bits is reg2.
  # So the ModR/M encoding is something like
  # xx  xxx  xxx
  # mod reg2  reg1

  [ "\x00\xc0",           2, $reg2, [ $sreg1b ] ], # add BYTE reg1, reg2
  [ "\x01\xc0",           2, $reg2, [ $sreg1 ]  ], # /* addl %reg2,%reg1 */
  [ "\x02\xc0",           2, $reg2, [ $sreg2b ] ], # add BYTE reg2, reg1
  [ "\x03\xc0",           2, $reg2, [ $sreg2 ]  ], # add reg2, reg1
  [ "\x04",               2, $none, [ $eax ]    ], # /* addb $imm8,%al */
  [ "\x05",               5, $none, [ $eax ]    ], # /* addl $imm32,%eax */
                                          
  [ "\x06",               1, $none, [ $esp ]    ], # /* push %es */
  # \x07 -> pop es                          
                                          
  [ "\x08\xc0",           2, $reg2, [ $sreg1b ] ], # /* orb %reg2,%reg1 */
  [ "\x09\xc0",           2, $reg2, [ $sreg1 ]  ], # /* orl %reg2,%reg1 */
  [ "\x0a\xc0",           2, $reg2, [ $sreg2b ] ], # or BYTE reg2, reg1
  [ "\x0b\xc0",           2, $reg2, [ $sreg2 ]  ], # or reg2, reg1
                                          
  [ "\x0c",               2, $none, [ $eax ]    ], # /* orb $imm8,%al */
  [ "\x0d",               5, $none, [ $eax ]    ], # /* orl $imm32,%eax */
                                          
  [ "\x0e",               1, $none, [ $esp ]    ], # /* push %cs */
  # \x0f -> pop cs / invalid                 
                                          
  [ "\x10\xc0",           2, $reg2, [ $sreg1b ] ], # adc BYTE reg1, reg2
  [ "\x11\xc0",           2, $reg2, [ $sreg1 ]  ], # adc reg1, reg2
  [ "\x12\xc0",           2, $reg2, [ $sreg2b ] ], # adc BYTE reg2, reg1
  [ "\x13\xc0",           2, $reg2, [ $sreg2 ]  ], # adc reg2, reg1
  [ "\x14",               2, $none, [ $eax ]    ], # /* adc $imm8,%al */
  [ "\x15",               5, $none, [ $eax ]    ], # /* adc $imm32,%eax */
                                          
  [ "\x16",               1, $none, [ $esp ]    ], # /* push %ss */
  # \x17 -> pop ss                          
                                          
  [ "\x18\xc0",           2, $reg2, [ $sreg1b ] ], # sbb BYTE reg1, reg2
  [ "\x19\xc0",           2, $reg2, [ $sreg1 ]  ], # sbb reg1, reg2
  [ "\x1a\xc0",           2, $reg2, [ $sreg2b ] ], # sbb BYTE reg2, reg1
  [ "\x1b\xc0",           2, $reg2, [ $sreg2 ]  ], # sbb reg2, reg1
  [ "\x1c",               2, $none, [ $eax ]    ], # /* sbbb $imm8,%al */
  [ "\x1d",               5, $none, [ $eax ]    ], # /* sbbl $imm32,%eax */
                                          
  [ "\x1e",               1, $none, [ $esp ]    ], # /* push %ds */
  # \x1f -> pop ds                          
                                          
  [ "\x20\xc0",           2, $reg2, [ $sreg1b ] ], # /* andb %reg2,%reg1 */
  [ "\x21\xc0",           2, $reg2, [ $sreg1 ]  ], # /* andl %reg2,%reg1 */
  [ "\x22\xc0",           2, $reg2, [ $sreg2b ] ], # and BYTE reg2, reg1
  [ "\x23\xc0",           2, $reg2, [ $sreg2 ]  ], # and reg2, reg1
  [ "\x24",               2, $none, [ $eax ]    ], # and al, imm8
  [ "\x25",               5, $none, [ $eax ]    ], # and eax, imm32
                                          
  # \x26 es segment override prefix           
  [ "\x27",               1, $none, [ $eax ]    ], # daa
                                          
  [ "\x28\xc0",           2, $reg2, [ $sreg1b ] ], # /* subb %reg2,%reg1 */
  [ "\x29\xc0",           2, $reg2, [ $sreg1 ]  ], # /* subl %reg2,%reg1 */
  [ "\x2a\xc0",           2, $reg2, [ $sreg2b ] ], # sub BYTE reg2, reg1
  [ "\x2b\xc0",           2, $reg2, [ $sreg2 ]  ], # sub reg2, reg1
  [ "\x2c",               2, $none, [ $eax ]    ], # sub al, imm8
  [ "\x2d",               5, $none, [ $eax ]    ], # sub eax, imm32

  # \x2e cs segment override prefix
  [ "\x2f",               1, $none, [ $eax ]    ], # /* # das */
                                          
  [ "\x30\xc0",           2, $reg2, [ $sreg1b ] ], # /* xorb %reg2,%reg1 */
  [ "\x31\xc0",           2, $reg2, [ $sreg1 ]  ], # /* xorl %reg2,%reg1 */
  [ "\x32\xc0",           2, $reg2, [ $sreg2b ] ], # xor BYTE reg2, reg1
  [ "\x33\xc0",           2, $reg2, [ $sreg2 ]  ], # xor reg2, reg1
  [ "\x34",               2, $none, [ $eax ]    ], # xor al, imm8
  [ "\x35",               5, $none, [ $eax ]    ], # xor eax, imm32
                                          
  # \x36 ss segment override prefix           
  [ "\x37",               1, $none, [ $eax ]    ], # aaa
                                          
  [ "\x38\xc0",           2, $reg2, [ ]         ], # /* cmpb %reg2,%reg1 */
  [ "\x39\xc0",           2, $reg2, [ ]         ], # /* cmpl %reg2,%reg1 */
  [ "\x3a\xc0",           2, $reg2, [ ]         ], # cmp BYTE reg2, reg1
  [ "\x3b\xc0",           2, $reg2, [ ]         ], # cmp reg2, reg1
  [ "\x3c",               2, $none, [ ]         ], # /* cmpb $imm8,%al */
  [ "\x3d",               5, $none, [ ]         ], # /* cmpl $imm32,%eax */
                                          
  # \x3e ds segment override prefix           
  [ "\x3f",               1, $none, [ $eax ]    ], # aas
                                          
  # \x40 -> \x47                            
  [ "\x40",               1, $reg1, [ $sreg1 ]  ], # /* incl %reg1 */
  # \x48 -> \x4f                            
  [ "\x48",               1, $reg1, [ $sreg1 ]  ], # /* decl %reg1 */
  # \x50 -> \x57                            
  [ "\x50",               1, $reg1, [ $esp ]    ], # /* pushl %reg1 */
  # \x58 -> \x5f
  [ "\x58",               1, $reg1, [ $esp, $sreg1 ] ], # /* # pop reg1 */

  [ "\x60",               1, $none, [ $esp ]    ], # /* # pusha */
  # \x61 -> popa
  # \x62 -> bound
  # \x63 -> arpl (priv..)
  # \x64 -> fs segment override prefix
  # \x65 -> gs segnment override prefix

  # prefixin mixin
  [ "\x66",               2, $prefix | $osize | $none, [ ], \&_InsHandlerPrefix ], # operand size
  [ "\x67",               2, $prefix | $asize | $none, [ ], \&_InsHandlerPrefix ], # address size

  [ "\x68",               5, $none, [ $esp ]    ], # /* pushl $imm32 */
  [ "\x69\xc0",           6, $reg2, [ $sreg2 ]  ], # imul reg2, reg1, imm32
  [ "\x6a",               2, $none, [ $esp ]    ], # push BYTE imm8
  [ "\x6b\xc0",           3, $reg2, [ $sreg2 ]  ], # imul reg2, reg1, imm8
  # \x6c -> \x6f -> insb, insd, outsb, outsd

  # \x70 -> \x7f conditional jmpy jmpy
  [ "\x70",               2, $osize | $none, [ ], \&_InsHandlerJmp ], # jo
  [ "\x71",               2, $osize | $none, [ ], \&_InsHandlerJmp ], # jno
  [ "\x72",               2, $osize | $none, [ ], \&_InsHandlerJmp ], # jc
  [ "\x73",               2, $osize | $none, [ ], \&_InsHandlerJmp ], # jnc
  [ "\x74",               2, $osize | $none, [ ], \&_InsHandlerJmp ], # jz
  [ "\x75",               2, $osize | $none, [ ], \&_InsHandlerJmp ], # jnz
  [ "\x76",               2, $osize | $none, [ ], \&_InsHandlerJmp ], # jna
  [ "\x77",               2, $osize | $none, [ ], \&_InsHandlerJmp ], # ja
  [ "\x78",               2, $osize | $none, [ ], \&_InsHandlerJmp ], # js
  [ "\x79",               2, $osize | $none, [ ], \&_InsHandlerJmp ], # jns
  [ "\x7a",               2, $osize | $none, [ ], \&_InsHandlerJmp ], # jpe
  [ "\x7b",               2, $osize | $none, [ ], \&_InsHandlerJmp ], # jpo
  [ "\x7c",               2, $osize | $none, [ ], \&_InsHandlerJmp ], # jl
  [ "\x7d",               2, $osize | $none, [ ], \&_InsHandlerJmp ], # jnl
  [ "\x7e",               2, $osize | $none, [ ], \&_InsHandlerJmp ], # jng
  [ "\x7f",               2, $osize | $none, [ ], \&_InsHandlerJmp ], # jg

  # \x80 BYTE reg1, imm8
  [ "\x80\xc0",           3, $reg1, [ $sreg1b ] ], # /* addb $imm8,%reg1 */
  [ "\x80\xc8",           3, $reg1, [ $sreg1b ] ], # /* orb $imm8,%reg1 */
  [ "\x80\xd0",           3, $reg1, [ $sreg1b ] ], # adc BYTE reg1, imm8
  [ "\x80\xd8",           3, $reg1, [ $sreg1b ] ], # /* sbbb $imm8,%reg1 */
  [ "\x80\xe0",           3, $reg1, [ $sreg1b ] ], # /* andb $imm8,%reg1 */
  [ "\x80\xe8",           3, $reg1, [ $sreg1b ] ], # /* subb $imm8,%reg1 */
  [ "\x80\xf0",           3, $reg1, [ $sreg1b ] ], # /* xorb $imm8,%reg1 */
  [ "\x80\xf8",           3, $reg1, [ ] ], # /* cmpb $imm8,%reg1 */

  # \x81 reg1, imm32
  [ "\x81\xc0",           6, $reg2, [ $sreg1 ] ], # /* addl $imm32,%reg1 */
  [ "\x81\xc8",           6, $reg1, [ $sreg1 ] ], # /* orl $imm32,%reg1 */
  [ "\x81\xd0",           6, $reg1, [ $sreg1 ] ], # adc reg1, imm32
  [ "\x81\xd8",           6, $reg1, [ $sreg1 ] ], # /* sbbl $imm32,%reg1 */
  [ "\x81\xe0",           6, $reg1, [ $sreg1 ] ], # /* andl $imm32,%reg1 */
  [ "\x81\xe8",           6, $reg1, [ $sreg1 ] ], # /* subl $imm32,%reg1 */
  [ "\x81\xf0",           6, $reg1, [ $sreg1 ] ], # /* xorl $imm32,%reg1 *
  [ "\x81\xf8",           6, $reg1, [ ] ], # /* cmpl $imm32,%reg1 */

  # \x82 ?

  # \x38 reg1, imm8
  [ "\x83\xc0",           3, $reg1, [ $sreg1 ] ], # add reg1, imm8
  [ "\x83\xc8",           3, $reg1, [ $sreg1 ] ], # or reg1, imm8
  [ "\x83\xd0",           3, $reg1, [ $sreg1 ] ], # adc reg1, imm8
  [ "\x83\xd8",           3, $reg1, [ $sreg1 ] ], # sbb reg1, imm8
  [ "\x83\xe0",           3, $reg1, [ $sreg1 ] ], # and reg1, imm8
  [ "\x83\xe8",           3, $reg1, [ $sreg1 ] ], # sub reg1, imm8
  [ "\x83\xf0",           3, $reg1, [ $sreg1 ] ], # xor reg1, imm8
  [ "\x83\xf8",           3, $reg1, [ ] ], # cmp reg1, imm8

  [ "\x84\xc0",           2, $reg2, [ ] ], # /* testb %reg2,%reg1 */
  [ "\x85\xc0",           2, $reg2, [ ] ], # /* testl %reg2,%reg1 */

  [ "\x86\xc0",           2, $reg2, [ $sreg1b, $sreg2b ] ], # xchg BYTE reg2, BYTE reg1
  [ "\x87\xc0",           2, $reg2, [ $sreg1, $sreg2 ]   ], # xchg reg2, reg1

  [ "\x88\xc0",           2, $reg2, [ $sreg1b ] ], # /* movb %reg2,%reg1 */
  [ "\x89\xc0",           2, $reg2, [ $sreg1 ]  ], # /* movl %reg2,%reg1 */

  # \x90 -> \x97
  # xchg eax, eax == 0x90 == nop... fancy
  [ "\x90",               1, $reg1, [ $eax, $sreg1 ] ], # /* # xchg eax,reg1 */

  [ "\x98",               1, $none, [ $eax ]    ], # /* # cwde */
  [ "\x99",               1, $none, [ $edx ]    ], # /* # cdq */

  # \x9a call
  [ "\x9b",               1, $none, [ ]         ], # /* # wait */
  [ "\x9c",               1, $none, [ $esp ]    ], # /* # pushf */

  # XXX \x9d popf safe?
  # XXX \x9e sahf safe?
  [ "\x9f",               1, $none, [ $eax ]    ], # /* # lahf */

  # \xa0 -> mov al,  [imm32]
  # \xa1 -> mov eax, [imm32]
  # \xa2 -> mov [imm32], al
  # \xa3 -> mov [imm32], eax
  # \xa4 -> movsb
  # \xa5 -> movsd
  # \xa6 -> cmpsb
  # \xa7 -> cmpsd

  [ "\xa8",               2, $none, [ ]         ], # /* testb $imm8,%al */
  [ "\xa9",               5, $none, [ ]         ], # /* testl $imm32,%eax */
  # \xb0 -> \xb7
  [ "\xb0",               2, $reg1, [ $sreg1b ] ], # /* movb $imm8,%reg1 */
  # \xb8 -> \xbf
  [ "\xb8",               5, $reg1, [ $sreg1 ]  ], # /* movl $imm32,%reg1 */

  # \xc0 BYTE reg1, imm8
  [ "\xc0\xc0",           3, $reg1, [ $sreg1b ] ], # rol BYTE reg1, imm8
  [ "\xc0\xc8",           3, $reg1, [ $sreg1b ] ], # ror BYTE reg1, imm8
  [ "\xc0\xd0",           3, $reg1, [ $sreg1b ] ], # rcl BYTE reg1, imm8
  [ "\xc0\xd8",           3, $reg1, [ $sreg1b ] ], # rcr BYTE reg1, imm8
  [ "\xc0\xe0",           3, $reg1, [ $sreg1b ] ], # shl BYTE reg1, imm8
  [ "\xc0\xe8",           3, $reg1, [ $sreg1b ] ], # shr BYTE reg1, imm8
  # \xc0\xf0 ? deadspace? sal == shl.... so....
  [ "\xc0\xf8",           3, $reg1, [ $sreg1b ] ], # sar BYTE reg1, imm8

  # \xc1 reg1, imm8
  [ "\xc1\xc0",           3, $reg2, [ $sreg1 ] ], # rol reg1, imm8
  [ "\xc1\xc8",           3, $reg1, [ $sreg1 ] ], # ror reg1, imm8
  [ "\xc1\xd0",           3, $reg1, [ $sreg1 ] ], # rcl reg1, imm8
  [ "\xc1\xd8",           3, $reg1, [ $sreg1 ] ], # rcr reg1, imm8
  [ "\xc1\xe0",           3, $reg1, [ $sreg1 ] ], # shl reg1, imm8
  [ "\xc1\xe8",           3, $reg1, [ $sreg1 ] ], # shr reg1, imm8
  # \xc1\xf0 ? deadspace? sal == shl.... so....
  [ "\xc1\xf8",           3, $reg1, [ $sreg1 ] ], # sar reg1, imm8

  # \xc2 ret word distance
  # \xc3 ret
  # \xc4 les
  # \xc5 lds
  # \xc8 enter

  # yeah, these are bad enough to leave out...
#  [ "\xc9",               1, $none, [ $esp, $ebp ] ], # leave

  # \xca, \xcb retf
  # \xcc int3
  # \xcd int
  # \xce into
  # \xcf iret

  # \xd0 BYTE reg1, 1
  [ "\xd0\xc0",           2, $reg1, [ $sreg1b ] ], # rol BYTE reg1, 1
  [ "\xd0\xc8",           2, $reg1, [ $sreg1b ] ], # ror BYTE reg1, 1
  [ "\xd0\xd0",           2, $reg1, [ $sreg1b ] ], # rcl BYTE reg1, 1
  [ "\xd0\xd8",           2, $reg1, [ $sreg1b ] ], # rcr BYTE reg1, 1
  [ "\xd0\xe0",           2, $reg1, [ $sreg1b ] ], # shl BYTE reg1, 1
  [ "\xd0\xe8",           2, $reg1, [ $sreg1b ] ], # shr BYTE reg1, 1
  # \xd0\xf0 ? deadspace? sal == shl.... so....
  [ "\xd0\xf8",           2, $reg1, [ $sreg1b ] ], # sar BYTE reg1, 1

  # \xd1 reg1, 1
  [ "\xd1\xc0",           2, $reg1, [ $sreg1 ] ], # rol reg1, 1
  [ "\xd1\xc8",           2, $reg1, [ $sreg1 ] ], # ror reg1, 1
  [ "\xd1\xd0",           2, $reg1, [ $sreg1 ] ], # rcl reg1, 1
  [ "\xd1\xd8",           2, $reg1, [ $sreg1 ] ], # rcr reg1, 1
  [ "\xd1\xe0",           2, $reg1, [ $sreg1 ] ], # shl reg1, 1
  [ "\xd1\xe8",           2, $reg1, [ $sreg1 ] ], # shr reg1, 1
  # \xd1\xf0 ? deadspace? sal == shl.... so....
  [ "\xd1\xf8",           2, $reg1, [ $sreg1 ] ], # sar reg1, 1
 
  # \xd2 BYTE reg1, cl
  [ "\xd2\xc0",           2, $reg1, [ $sreg1b ] ], # rol BYTE reg1, cl
  [ "\xd2\xc8",           2, $reg1, [ $sreg1b ] ], # ror BYTE reg1, cl
  [ "\xd2\xd0",           2, $reg1, [ $sreg1b ] ], # rcl BYTE reg1, cl
  [ "\xd2\xd8",           2, $reg1, [ $sreg1b ] ], # rcr BYTE reg1, cl
  [ "\xd2\xe0",           2, $reg1, [ $sreg1b ] ], # shl BYTE reg1, cl
  [ "\xd2\xe8",           2, $reg1, [ $sreg1b ] ], # shr BYTE reg1, cl
  # \xd2\xf0 ? deadspace? sal == shl.... so....
  [ "\xd2\xf8",           2, $reg1, [ $sreg1b ] ], # sar BYTE reg1, cl

  # \xd3 reg1, cl
  [ "\xd3\xc0",           2, $reg1, [ $sreg1 ] ], # rol reg1, cl
  [ "\xd3\xc8",           2, $reg1, [ $sreg1 ] ], # ror reg1, cl
  [ "\xd3\xd0",           2, $reg1, [ $sreg1 ] ], # rcl reg1, cl
  [ "\xd3\xd8",           2, $reg1, [ $sreg1 ] ], # rcr reg1, cl
  [ "\xd3\xe0",           2, $reg1, [ $sreg1 ] ], # shl reg1, cl
  [ "\xd3\xe8",           2, $reg1, [ $sreg1 ] ], # shr reg1, cl
  # \xd2\xf0 ? deadspace? sal == shl.... so....
  [ "\xd3\xf8",           2, $reg1, [ $sreg1 ] ], # sar reg1, cl
 
  [ "\xd4",               2, $none, [ $eax ]    ], # /* aam $imm8 */
  [ "\xd5",               2, $none, [ $eax ]    ], # /* aad $imm8 */
  [ "\xd6",               1, $none, [ $eax ]    ], # /* # salc */

  # \xd7 -> xlatb
  # \xd8 -> fdivr
  # ... more fpu stuff

  # \xe0 loopne
  # \xe1 loope
  # \xe2 loop

  [ "\xe3",               2, $osize | $none, [ ], \&_InsHandlerJmp ], # jecxz
  # \xe4 -> \xe7 in/out
  # \xe8 call
  # \xe9, \xea jmp
  [ "\xeb",               2, $osize | $none, [ ], \&_InsHandlerJmp ], # jmp byte offset
  # \xec, \xed, \xef in/out
  # \xf0 lock prefix (priv)
  # \xf1 int1
  # \xf2 repne prefix
  # \xf3 rep prefix
  # \xf4 hlt (priv..)

  [ "\xf5",               1, $none, [ ]         ], # /* cmc */
  [ "\xf6\xc0",           3, $reg1, [ ]         ], # /* testb $imm8,%reg1 */
  # \xf6\xc8 deadspace?
  [ "\xf6\xd0",           2, $reg1, [ $sreg1b ] ], # /* notb %reg1 */
  [ "\xf6\xd8",           2, $reg1, [ $sreg1b ] ], # neg BYTE reg1
  [ "\xf6\xe0",           2, $reg1, [ $eax ]    ], # /* mulb %reg1 */
  [ "\xf6\xe8",           2, $reg1, [ $eax ]    ], # imul BYTE reg1
  # \xf6\xf0 -> \xf6\xff div/idiv
  [ "\xf7\xc0",           6, $reg1, [ ]         ], # /* testl $imm32,%reg1 */
  [ "\xf7\xd0",           2, $reg1, [ $sreg1 ]  ], # /* notl %reg1 */
  [ "\xf7\xd8",           2, $reg1, [ $sreg1 ]  ], # neg reg1
  [ "\xf7\xe0",           2, $reg1, [ $eax, $edx ] ], # /* mull %reg1 */
  [ "\xf7\xe8",           2, $reg1, [ $eax, $edx ] ], # imul reg1
  [ "\xf8",               1, $none, [ ]         ], # /* clc */
  [ "\xf9",               1, $none, [ ]         ], # /* stc */
  # \xfa cli
  # \xfb sti
  [ "\xfc",               1, $none, [ ]         ], # /* cld */
  [ "\xfd",               1, $none, [ ]         ], # /* std */
  [ "\xfe\xc0",           2, $reg1, [ $sreg1b ] ], # /* incb %reg1 */
  [ "\xfe\xc8",           2, $reg1, [ $sreg1b ] ], # /* decb %reg1 */

  [ "\xff\xc0",           2, $reg1, [ $sreg1 ] ], # inc reg
  [ "\xff\xc8",           2, $reg1, [ $sreg1 ] ], # dec reg
  # \xff\xd0 -> \xff\xd8 call reg1, deadspace?
  # \xff\xe0 -> \xff\xe8 jmp reg1, deadspace?
  [ "\xff\xf0",           2, $reg1, [ $esp ] ], # push reg
  # \xff\xf8 deadspace?
];

sub _TableLength {
  my $self = shift;
  return(scalar(@{$table}));
}

sub _BadRegs {
#  return([ ]);
  return([$ebp, $esp]);
}

sub _BadChars {
  return('');
}

sub _GenerateSled {
  my $self = shift;
  my $len = shift;

  return if($len <= 0);

  my $data = "\x00" x $len;
  my $pos = $len;

  my ($c1, $c2) = (0, 1);

  my $lastIndex;

  while($pos > 0) {
    my $index = int(rand(@{$table}));

    next if(!$self->_CheckIns($index, $pos, $len));

    my $code = $table->[$index]->[0];
    my $codeLen = length($code);
    my $insLen = $table->[$index]->[1];

    # Check to see if it's a one byte codelen type that wants SetRegs called
    if($self->_InsHandler(0, $index, $pos, $len, $data, $lastIndex)) {
      if($debug == 2) {
        $synWeight = ($c1 / $c2) ** 2;
      }
      next if(int(rand($synWeight)) != 0);
      $pos--;
      substr($data, $pos, 1, $self->_SetRegs(substr($code, -1, 1), $index));
      print STDERR "." if($debug);
      $c1++;
    }
    else {
      # Check to see if the byte that already exists will make for a valid
      # ending byte to our current instruction
      next if(!$self->_InsHandler(1, $index, $pos, $len, $data, $lastIndex));
  
      $pos -= $codeLen;
      substr($data, $pos, $codeLen, $code);
      print STDERR "+" if($debug);
      $c2++;
    }
    $lastIndex = $index;

  }

  print STDERR "\n" if($debug);
  return($data);
}


sub _CheckIns {
  my $self = shift;
  my $index = shift;
  my $pos = shift;
  my $len = shift;

  my $code = $table->[$index]->[0];
  my $codeLen = length($code);
  my $insLen = $table->[$index]->[1];


  my $flags = $table->[$index]->[2];

  # instruction would run off the end
  return(0) if(($insLen - 1) > ($len - $pos));

  # instruction would run off the front
  return(0) if($codeLen > $pos);
  # test to see if the instruction always modifies a bad register.
  return(0) if($self->_SmashCheck($index));

  if(($flags & 0x03) == $reg2) {
    return($self->_CheckInsReg2($index, $pos, $len));
  }
  elsif(($flags & 0x03) == $reg1) {
    return($self->_CheckInsReg1($index, $pos, $len));
  }
  else {
    return($self->_CheckInsNone($index, $pos, $len));
  }
  # ...
  return(1);
}


sub _CheckInsNone {
  my $self = shift;
  my $index = shift;

  my $code = $table->[$index]->[0];
  my $codeLen = length($code);

  # make sure the instruction doesn't have any bad characters
  return(0) if(Pex::Text::BadCharCheck($self->_BadChars, $code));
  return(1);
}

sub _CheckInsReg2 {
  my $self = shift;
  my $index = shift;

  my $code = $table->[$index]->[0];
  my $codeLen = length($code);
  my $flags = $table->[$index]->[2];


  # Make sure the static portion of the instruction doesn't have bad bytes
  return(0) if(Pex::Text::BadCharCheck(
    $self->_BadChars,
    substr($code, $codeLen - 2, $codeLen - 1)
  ));

  # check to make sure that a generation is possible w/ current constraints
  return(0) if(!$self->_CheckReg2Possible($index, substr($code, -1, 1)));

  return(1);
}

sub _CheckInsReg1 {
  my $self = shift;
  my $index = shift;

  my $code = $table->[$index]->[0];
  my $codeLen = length($code);

  # Make sure the static portion of the instruction doesn't have bad bytes
  return(0) if(Pex::Text::BadCharCheck(
    $self->_BadChars,
    substr($code, $codeLen - 2, $codeLen - 1)
  ));

  # check to make sure that a generation is possible w/ current constraints
  return(0) if(!$self->_CheckReg1Possible($index, substr($code, -1, 1)));
  return(1);
}

# Make sure that for a given byte of a two register instruction, there is
# atleast one generation possible.
sub _CheckReg2Possible {
  my $self = shift;
  my $index = shift;
  my $byte = shift;

  for(my $i = 0; $i < 8; $i++) {
    next if($self->_SmashCheckReg2($index, $i));
    return(1) if($self->_CheckReg1Possible($index, $byte | chr($i << 3)));
  }
  return(0);
}

# Make sure that given a byte for a single register instruction, there is a 
# generation possible.
sub _CheckReg1Possible {
  my $self = shift;
  my $index = shift;
  my $byte = shift;

  my $badChars = $self->_BadChars;

  for(my $i = 0; $i < 8; $i++) {
    next if($self->_SmashCheckReg1($index, $i));
    return(1) if(!Pex::Text::BadCharCheck($badChars, $byte | chr($i)));
  }
  return(0);
}



# Types:
# 0 = Are you a single byte (maybe plus immediate), ie should I call SetRegs?
# 1 = 

sub _InsHandler {
  my $self = shift;
  my $type = shift;
  my $index = shift;

  my $handler = $table->[$index]->[4];
  # call default handler
  if(!defined($handler)) {
    return($self->_InsHandlerDefault($type, $index, @_));
  }
  else {
    return(&{$handler}($self, $type, $index, @_));
  }
}

sub _InsHandlerDefault {
  my $self = shift;
  my $type = shift;
  my $index = shift;
  my $pos = shift;
  my $len = shift;
  my $data = shift;

  my $code = $table->[$index]->[0];
  my $codeLen = length($code);

  # The general case of codeLen == 1 is that we want to call SetRegs, since the
  # operands are part of the opcode, n such
  if($type == 0) {
    return(1) if($codeLen == 1);
    return(0);
  }

  # Is instruction valid?
  elsif($type == 1) {
    return($self->_ValidReg(
      substr($data, $pos, 1),
      substr($code, $codeLen - 1, 1),
      $index
    ));
  }
}

sub _InsHandlerJmp {
  my $self = shift;
  my $type = shift;
  my $index = shift;
  my $pos = shift;
  my $len = shift;
  my $data = shift;

  # we aren't the normal type, we never want SetRegs called...
  if($type == 0) {
    return(0);
  }
  elsif($type == 1) {
    my $byte = substr($data, $pos, 1);

    return(0) if(ord($byte) > 0x7f);
    return(0) if(ord($byte) > ($len - $pos - 1));

    return(1);
  }
}

sub _InsHandlerPrefix {
  my $self = shift;
  my $type = shift;
  my $index = shift;
  my $pos = shift;
  my $len = shift;
  my $data = shift;
  my $lastIndex = shift;

  if($type == 0) {
    return(0);
  }
  elsif($type == 1) {
    my $code = $table->[$index]->[0];
    my $codeLen = length($code);
    my $flags = $table->[$index]->[2];
    my $lastFlags = $table->[$lastIndex]->[2];
    # don't support multiple prefixes for now.  In theory you can, the problem
    # is you need to check the flags not only for the old prefix byte, but
    # also the instruction.  So right now since we only have lastIndex, we
    # could check and see that \x66 couldn't allow another \x66, but couldn't
    # check to make sure the actual instruction behind it couldn't allow a
    # certain flag.  You'd need to iterate the prefixes and the instruction,
    # something that isn't happening right now...
    return(0) if($lastFlags & $prefix);
    # this probably isn't the best way but I'm lazy, detect which instruction
    # based on the flags (because prefixes can't repeat)
    if($flags & $osize) {
      return(0) if($lastFlags & $osize);
    }
    elsif($flags & $asize) {
      return(0) if($lastFlags & $asize);
    }
    return(1);
  }
}


# Check to see if a instruction always modifies a BadRegs
sub _SmashCheck {
  my $self = shift;
  my $index = shift;

  foreach my $r (@{$table->[$index]->[3]}) {
    return(1) if($self->_BadRegCheck($r));
  }
  return(0);
}

# check to see if an instruction has a $reg smash, and if so if the passed
# register is in BadRegs
sub _SmashCheckReg1 {
  my $self = shift;
  my $index = shift;
  my $rreg = shift;

  foreach my $r (@{$table->[$index]->[3]}) {
    return(1) if($r == $sreg1 && $self->_BadRegCheck($rreg));
    return(1) if($r == $sreg1b && $self->_BadRegCheck($rreg % 4));
  }
  return(0);
}

sub _SmashCheckReg2 {
  my $self = shift;
  my $index = shift;
  my $rreg = shift;

  foreach my $r (@{$table->[$index]->[3]}) {
    return(1) if($r == $sreg2 && $self->_BadRegCheck($rreg));
    return(1) if($r == $sreg2b && $self->_BadRegCheck($rreg % 4));
  }
  return(0);
}



# Check to see if an aribitrary register number is in BadRegs
sub _BadRegCheck {
  my $self = shift;
  my $r = shift;

  my $badRegs = $self->_BadRegs;
  foreach my $breg (@{$badRegs}) {
    return(1) if($r == $breg);
  }
  return(0);
}

# You must have checked (with say, _CheckIns) that a valid generation is
# actually possible, otherwise you could get stuck in a loop...
# XXX this could be made a lot more efficent...
sub _SetRegs {
  my $self = shift;
  my $byte = shift;
  my $index = shift;

  my $flags = $table->[$index]->[2];

  if(($flags & 0x03) == $reg2) {
    my ($r1, $r2, $r) = (0, 0, 0);
    do {
      $r2 = int(rand(8));
      $r1 = int(rand(8));
      $r = $r2 << 3 | $r1;
    } while($self->_SmashCheckReg2($index, $r2)
        || $self->_SmashCheckReg1($index, $r1)
        || Pex::Text::BadCharCheck($byte | chr($r)));

    return($byte | chr($r));
  }

  elsif(($flags & 0x03) == $reg1) {
    my $r = 0;
    do {
      $r = int(rand(8));
    } while($self->_SmashCheckReg1($index, $r)
        || Pex::Text::BadCharCheck($byte | chr($r)));

    return($byte | chr($r));
  }

  return($byte);
}

sub _ValidReg {
  my $self = shift;
  my $byte = shift;
  my $ins = shift;
  my $index = shift;

  my $flags = $table->[$index]->[2];

  if(($flags & 0x03) == $reg2) {
    return(0) if(($byte & 0xc0) ne $ins);
    return(0) if(
      $self->_SmashCheckReg1($index, $byte & 0x07)
      || $self->_SmashCheckReg2($index, ($byte & 0x38) >> 3)
    );
  }
  elsif(($flags & 0x03) == $reg1) {
    return(0) if(($byte & 0xf8) ne $ins);
    return(0) if($self->_SmashCheckReg1($index, $byte & 0x07));  
  }
  else {
    return(0) if($byte ne $ins);
  }

  return(1);
}

1;
