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

my $none  = 0;
my $reg1  = 1;
my $reg2  = 2;
# Is the smash register location reversed? (only for reg2's?)
my $regrev = 4;
my $regb = 8;

my $eax = 0;
my $ecx = 1;
my $edx = 2;
my $ebx = 3;
my $esp = 4;
my $ebp = 5;
my $esi = 6;
my $edi = 7;
my $reg = 8;

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
my $osize = $regb << 1; # \x66
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
  # comment naming convention, reg2 is the low 3 bits and reg1 is higher
  [ "\x00\xc0",           2, $regb | $reg2, [ $reg ] ], # add BYTE reg2, reg1
  [ "\x01\xc0",           2, $reg2, [ $reg ] ], # /* addl %reg1,%reg2 */
  [ "\x02\xc0",           2, $regb | $regrev | $reg2, [ $reg ] ], # add BYTE reg1, reg2
  [ "\x03\xc0",           2, $regrev | $reg2, [ $reg ] ], # add reg1, reg2
  [ "\x04",               2, $regb | $none, [ $eax ] ], # /* addb $imm8,%al */
  [ "\x05",               5, $none, [ $eax ] ], # /* addl $imm32,%eax */

  [ "\x06",               1, $none, [ $esp ] ], # /* push %es */
  # \x07 -> pop es

  [ "\x08\xc0",           2, $regb | $reg2, [ $reg ] ], # /* orb %reg1,%reg2 */
  [ "\x09\xc0",           2, $reg2, [ $reg ] ], # /* orl %reg1,%reg2 */
  [ "\x0a\xc0",           2, $regb | $regrev | $reg2, [ $reg ] ], # or BYTE reg1, reg2
  [ "\x0b\xc0",           2, $regrev | $reg2, [ $reg ] ], # or reg1, reg2

  [ "\x0c",               2, $none, [ $eax ] ], # /* orb $imm8,%al */
  [ "\x0d",               5, $none, [ $eax ] ], # /* orl $imm32,%eax */

  [ "\x0e",               1, $none, [ $esp ] ], # /* push %cs */
  # \x0f -> pop cs / invalid

  [ "\x10\xc0",           2, $regb | $reg2, [ $reg ] ], # adc BYTE reg2, reg1
  [ "\x11\xc0",           2, $reg2, [ $reg ] ], # adc reg2, reg1
  [ "\x12\xc0",           2, $regb | $regrev | $reg2, [ $reg ] ], # adc BYTE reg1, reg2
  [ "\x13\xc0",           2, $regrev | $reg2, [ $reg ] ], # adc reg1, reg2
  [ "\x14",               2, $none, [ $eax ] ], # /* adc $imm8,%al */
  [ "\x15",               5, $none, [ $eax ] ], # /* adc $imm32,%eax */

  [ "\x16",               1, $none, [ $esp ] ], # /* push %ss */
  # \x17 -> pop ss

  [ "\x18\xc0",           2, $regb | $reg2, [ $reg ] ], # sbb BYTE reg2, reg1
  [ "\x19\xc0",           2, $reg2, [ $reg ] ], # sbb reg2, reg1
  [ "\x1a\xc0",           2, $regb | $regrev | $reg2, [ $reg ] ], # sbb BYTE reg1, reg2
  [ "\x1b\xc0",           2, $regrev | $reg2, [ $reg ] ], # sbb reg1, reg2
  [ "\x1c",               2, $none, [ $eax ] ], # /* sbbb $imm8,%al */
  [ "\x1d",               5, $none, [ $eax ] ], # /* sbbl $imm32,%eax */

  [ "\x1e",               1, $none, [ $esp ] ], # /* push %ds */
  # \x1f -> pop ds

  [ "\x20\xc0",           2, $regb | $reg2, [ $reg ] ], # /* andb %reg1,%reg2 */
  [ "\x21\xc0",           2, $reg2, [ $reg ] ], # /* andl %reg1,%reg2 */
  [ "\x22\xc0",           2, $regb | $regrev | $reg2, [ $reg ] ], # and BYTE reg1, reg2
  [ "\x23\xc0",           2, $regrev | $reg2, [ $reg ] ], # and reg1, reg2
  [ "\x24",               2, $none, [ $eax ] ], # and al, imm8
  [ "\x25",               5, $none, [ $eax ] ], # and eax, imm32

  # \x26 es segment override prefix
  [ "\x27",               1, $none, [ $eax ] ], # daa

  [ "\x28\xc0",           2, $regb | $reg2, [ $reg ] ], # /* subb %reg1,%reg2 */
  [ "\x29\xc0",           2, $reg2, [ $reg ] ], # /* subl %reg1,%reg2 */

  [ "\x30\xc0",           2, $regb | $reg2, [ $reg ] ], # /* xorb %reg1,%reg2 */
  [ "\x31\xc0",           2, $reg2, [ $reg ] ], # /* xorl %reg1,%reg2 */
  [ "\x32\xc0",           2, $regb | $regrev | $reg2, [ $reg ] ], # xor BYTE reg1, reg2
  [ "\x33\xc0",           2, $regrev | $reg2, [ $reg ] ], # xor reg1, reg2
  [ "\x34",               2, $none, [ $eax ] ], # xor al, imm8
  [ "\x35",               5, $none, [ $eax ] ], # xor eax, imm32

  # \x36 ss segment override prefix
  [ "\x37",               1, $none, [ $eax ] ], # aaa

  [ "\x38\xc0",           2, $reg2, [ ] ], # /* cmpb %reg1,%reg2 */
  [ "\x39\xc0",           2, $reg2, [ ] ], # /* cmpl %reg1,%reg2 */
  [ "\x3a\xc0",           2, $regrev | $reg2, [ ] ], # cmp BYTE reg1, reg2
  [ "\x3b\xc0",           2, $regrev | $reg2, [ ] ], # cmp reg1, reg2
  [ "\x3c",               2, $none, [ ] ], # /* cmpb $imm8,%al */
  [ "\x3d",               5, $none, [ ] ], # /* cmpl $imm32,%eax */

  # \x3e ds segment override prefix
  [ "\x3f",               1, $none, [ $eax ] ], # aas

  # \x40 -> \x47
  [ "\x40",               1, $reg1, [ $reg ] ], # /* incl %reg1 */
  # \x48 -> \x4f
  [ "\x48",               1, $reg1, [ $reg ] ], # /* decl %reg1 */
  # \x50 -> \x57
  [ "\x50",               1, $reg1, [ $esp ] ], # /* pushl %reg1 */
  # \x58 -> \x5f
  [ "\x58",               1, $reg1, [ $esp, $reg ] ], # /* # pop reg1 */

  [ "\x60",               1, $none, [ $esp ] ], # /* # pusha */
  # \x61 -> popa
  # \x62 -> bound
  # \x63 -> arpl (priv..)
  # \x64 -> fs segment override prefix
  # \x65 -> gs segnment override prefix

  # prefixin mixin
  [ "\x66",               2, $prefix | $osize | $none, [ ], \&_InsHandlerPrefix ], # operand size
  [ "\x67",               2, $prefix | $asize | $none, [ ], \&_InsHandlerPrefix ], # address size

  [ "\x68",               5, $none, [ $esp ] ], # /* pushl $imm32 */
  [ "\x69\xc0",           6, $regrev | $reg2, [ $reg ] ], # imul reg1, reg2, imm32
  [ "\x6a",               2, $none, [ $esp ] ], # push BYTE imm8
  [ "\x6b\xc0",           3, $regrev | $reg2, [ $reg ] ], # imul reg1, reg2, imm8
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
  [ "\x80\xc0",           3, $regb | $reg1, [ $reg ] ], # /* addb $imm8,%reg1 */
  [ "\x80\xc8",           3, $regb | $reg1, [ $reg ] ], # /* orb $imm8,%reg1 */
  [ "\x80\xd0",           3, $regb | $reg1, [ $reg ] ], # adc BYTE reg1, imm8
  [ "\x80\xd8",           3, $regb | $reg1, [ $reg ] ], # /* sbbb $imm8,%reg1 */
  [ "\x80\xe0",           3, $regb | $reg1, [ $reg ] ], # /* andb $imm8,%reg1 */
  [ "\x80\xe8",           3, $regb | $reg1, [ $reg ] ], # /* subb $imm8,%reg1 */
  [ "\x80\xf0",           3, $regb | $reg1, [ $reg ] ], # /* xorb $imm8,%reg1 */
  [ "\x80\xf8",           3, $reg1, [ ] ], # /* cmpb $imm8,%reg1 */

  # \x81 reg1, imm32
  [ "\x81\xc0",           6, $reg2, [ $reg ] ], # /* addl $imm32,%reg1 */
  [ "\x81\xc8",           6, $reg1, [ $reg ] ], # /* orl $imm32,%reg1 */
  [ "\x81\xd0",           6, $reg1, [ $reg ] ], # adc reg1, imm32
  [ "\x81\xd8",           6, $reg1, [ $reg ] ], # /* sbbl $imm32,%reg1 */
  [ "\x81\xe0",           6, $reg1, [ $reg ] ], # /* andl $imm32,%reg1 */
  [ "\x81\xe8",           6, $reg1, [ $reg ] ], # /* subl $imm32,%reg1 */
  [ "\x81\xf0",           6, $reg1, [ $reg ] ], # /* xorl $imm32,%reg1 *
  [ "\x81\xf8",           6, $reg1, [ ] ], # /* cmpl $imm32,%reg1 */

  # \x82 ?

  # \x38 reg1, imm8
  [ "\x83\xc0",           3, $reg1, [ $reg ] ], # add reg1, imm8
  [ "\x83\xc8",           3, $reg1, [ $reg ] ], # or reg1, imm8
  [ "\x83\xd0",           3, $reg1, [ $reg ] ], # adc reg1, imm8
  [ "\x83\xd8",           3, $reg1, [ $reg ] ], # sbb reg1, imm8
  [ "\x83\xe0",           3, $reg1, [ $reg ] ], # and reg1, imm8
  [ "\x83\xe8",           3, $reg1, [ $reg ] ], # sub reg1, imm8
  [ "\x83\xf0",           3, $reg1, [ $reg ] ], # xor reg1, imm8
  [ "\x83\xf8",           3, $reg1, [ ] ], # cmp reg1, imm8

  [ "\x84\xc0",           2, $reg2, [ ] ], # /* testb %reg1,%reg2 */
  [ "\x85\xc0",           2, $reg2, [ ] ], # /* testl %reg1,%reg2 */


  [ "\x88\xc0",           2, $regb | $reg2, [ $reg ] ], # /* movb %reg1,%reg2 */
  [ "\x89\xc0",           2, $reg2, [ $reg ] ], # /* movl %reg1,%reg2 */
  [ "\xa8",               2, $none, [ ] ], # /* testb $imm8,%al */
  [ "\xa9",               5, $none, [ ] ], # /* testl $imm32,%eax */
  [ "\xb0",               2, $regb | $reg1, [ $reg ] ], # /* movb $imm8,%reg1 */
  [ "\xb8",               5, $reg1, [ $reg ] ], # /* movl $imm32,%reg1 */
  [ "\xd4",               2, $none, [ $eax ] ], # /* aam $imm8 */
  [ "\xd5",               2, $none, [ $eax ] ], # /* aad $imm8 */
  [ "\xf5",               1, $none, [ ] ], # /* cmc */
  [ "\xf6\xc0",           3, $reg1, [ ] ], # /* testb $imm8,%reg1 */
  [ "\xf6\xd0",           2, $regb | $reg1, [ $reg ] ], # /* notb %reg1 */
  [ "\xf6\xe0",           2, $reg1, [ $eax ] ], # /* mulb %reg1 */
  [ "\xf7\xc0",           6, $reg1, [ ] ], # /* testl $imm32,%reg1 */
  [ "\xf7\xd0",           2, $reg1, [ $reg ] ], # /* notl %reg1 */
  [ "\xf7\xe0",           2, $reg1, [ $eax, $edx ] ], # /* mull %reg1 */
  [ "\xf8",               1, $none, [ ] ], # /* clc */
  [ "\xf9",               1, $none, [ ] ], # /* stc */
  [ "\xfc",               1, $none, [ ] ], # /* cld */
  [ "\xfd",               1, $none, [ ] ], # /* std */
  [ "\xfe\xc0",           2, $regb | $reg1, [ $reg ] ], # /* incb %reg1 */
  [ "\xfe\xc8",           2, $regb | $reg1, [ $reg ] ], # /* decb %reg1 */

# added by spoon...
  # xchg eax, eax == 0x90 == nop... fancy
  [ "\x90",               1, $reg1, [ $eax, $reg ] ], # /* # xchg eax,reg1 */
  [ "\x99",               1, $none, [ $edx ] ], # /* # cdq */



  [ "\x2f",               1, $none, [ $eax ] ], # /* # das */
  [ "\x98",               1, $none, [ $eax ] ], # /* # cwde */
  [ "\x9f",               1, $none, [ $eax ] ], # /* # lahf */
  [ "\xd6",               1, $none, [ $eax ] ], # /* # salc */
  [ "\x9b",               1, $none, [ ] ], # /* # wait */

  [ "\x9c",               1, $none, [ $esp ] ], # /* # pushf */


# jmpy jmp jmp
  [ "\xeb",               2, $osize | $none, [ ], \&_InsHandlerJmp ], # jmp byte offset


];

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

  my $lastIndex;

  while($pos > 0) {
    my $index = int(rand(@{$table}));

    next if(!$self->_CheckIns($index, $pos, $len));

    my $code = $table->[$index]->[0];
    my $codeLen = length($code);
    my $insLen = $table->[$index]->[1];

    # Check to see if it's a one byte codelen type that wants SetRegs called
    if($self->_InsHandler(0, $index, $pos, $len, $data, $lastIndex)) {
      $pos--;
      substr($data, $pos, 1, $self->_SetRegs(substr($code, -1, 1), $index));
    }
    else {
      # Check to see if the byte that already exists will make for a valid
      # ending byte to our current instruction
      next if(!$self->_InsHandler(1, $index, $pos, $len, $data, $lastIndex));
  
      $pos -= $codeLen;
      substr($data, $pos, $codeLen, $code);
    }
    $lastIndex = $index;

  }

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
  return(0) if(!$self->_CheckReg2Possible(
    substr($code, -1, 1),
    ($flags & $regrev) ? 1 : 0,
    ($flags & $regb) ? 1 : 0,
  ));
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
  return(0) if(!$self->_CheckReg1Possible(substr($code, -1, 1)));
  return(1);
}

# Make sure that for a given byte of a two register instruction, there is
# atleast one generation possible.
sub _CheckReg2Possible {
  my $self = shift;
  my $byte = shift;
  my $reverse = @_ ? shift : 0;
  my $regbyte = @_ ? shift : 0;

  my $mod = $regbyte ? 4 : 8;

  for(my $i = 0; $i < 8; $i++) {
    next if($reverse && $self->_BadRegCheck($i % $mod));
    return(1) if($self->_CheckReg1Possible($byte + chr($i << 3), $reverse, $regbyte));
  }
  return(0);
}

# Make sure that given a byte for a single register instruction, there is a 
# generation possible.
sub _CheckReg1Possible {
  my $self = shift;
  my $byte = shift;
  my $reverse = @_ ? shift : 0;
  my $regbyte = @_ ? shift : 0;

  my $mod = $regbyte ? 4 : 8;
  my $badChars = $self->_BadChars;

  for(my $i = 0; $i < 8; $i++) {
    next if(!$reverse && $self->_BadRegCheck($i % $mod));
    return(1) if(!Pex::Text::BadCharCheck($badChars, $byte + chr($i)));
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
sub _SmashCheckReg {
  my $self = shift;
  my $index = shift;
  my $rreg = shift;

  foreach my $r (@{$table->[$index]->[3]}) {
    return(1) if($r == $reg && $self->_BadRegCheck($rreg));
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
    my $reverse = ($flags & $regrev) ? 1 : 0;
    my $bytereg = ($flags & $regb) ? 1 : 0;
    my $mod = $bytereg ? 4 : 8;
    my ($r1, $r2, $r) = (0, 0, 0);
    do {
      $r2 = int(rand(8));
      $r1 = int(rand(8));
      $r = $r2 << 3 + $r1;
    } while((!$reverse && $self->_BadRegCheck($r1 % $mod))
        || ($reverse && $self->_BadRegCheck($r2 % $mod))
        || Pex::Text::BadCharCheck($byte | chr($r)));

    return($byte | chr($r));
  }

  elsif(($flags & 0x03) == $reg1) {
    my $bytereg = ($flags & $regb) ? 1 : 0;
    my $mod = $bytereg ? 4 : 8;
    my $r = 0;
    do {
      $r = int(rand(8));
    } while($self->_BadRegCheck($r % $mod)
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
    my $reverse = ($flags & $regrev) ? 1 : 0;
    my $bytereg = ($flags & $regb) ? 1 : 0;
    my $mod = $bytereg ? 4 : 8;
    return(0) if(($byte & 0xc0) ne $ins);
    return(0) if(!$reverse && $self->_SmashCheckReg($index, ($reg & 0x07) % $mod));
    return(0) if($reverse && $self->_SmashCheckReg($index, (($reg & 0x38) >> 3) % $mod));
  }
  elsif(($flags & 0x03) == $reg1) {
    my $bytereg = ($flags & $regb) ? 1 : 0;
    my $mod = $bytereg ? 4 : 8;
    return(0) if(($byte & 0xf8) ne $ins);
    return(0) if($self->_SmashCheckReg($index, ($reg & 0x07) % $mod));  
  }
  else {
    return(0) if($byte ne $ins);
  }

  return(1);
}

1;
