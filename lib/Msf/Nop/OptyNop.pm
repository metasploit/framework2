#!/usr/bin/perl
package Msf::Nop::OptyNop;
use strict;
use base 'Msf::Nop';
use Pex::Text;

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

# someday this will all be leeter, but it's not so bad for now :)


my $table = [
  [ "\xfe\xc0",           2, $reg1, [ $reg ] ], # /* incb %reg1 */
  [ "\x66\x40",           2, $reg1, [ $reg ] ], # /* incw %reg1 */
  [ "\x40",               1, $reg1, [ $reg ] ], # /* incl %reg1 */
  [ "\xfe\xc8",           2, $reg1, [ $reg ] ], # /* decb %reg1 */
  [ "\x66\x48",           2, $reg1, [ $reg ] ], # /* decw %reg1 */
  [ "\x48",               1, $reg1, [ $reg ] ], # /* decl %reg1 */
  [ "\x66\x50",           2, $reg1, [ $esp ] ], # /* pushw %reg1 */
  [ "\x66\x68",           4, $none, [ $esp ] ], # /* pushw $imm16 */
  [ "\x50",               1, $reg1, [ $esp ] ], # /* pushl %reg1 */
  [ "\x68",               5, $none, [ $esp ] ], # /* pushl $imm32 */
  [ "\x88\xc0",           2, $reg2, [ $reg ] ], # /* movb %reg1,%reg2 */
  [ "\xb0",               2, $reg1, [ $reg ] ], # /* movb $imm8,%reg1 */
  [ "\x66\x89\xc0",       3, $reg2, [ $reg ] ], # /* movw %reg1,%reg2 */
  [ "\x66\xb8",           4, $reg1, [ $reg ] ], # /* movw $imm16,%reg1 */
  [ "\x89\xc0",           2, $reg2, [ $reg ] ], # /* movl %reg1,%reg2 */
  [ "\xb8",               5, $reg1, [ $reg ] ], # /* movl $imm32,%reg1 */
  [ "\x30\xc0",           2, $reg2, [ $reg ] ], # /* xorb %reg1,%reg2 */
  [ "\x80\xf0",           3, $reg1, [ $reg ] ], # /* xorb $imm8,%reg1 */
  [ "\x66\x31\xc0",       3, $reg2, [ $reg ] ], # /* xorw %reg1,%reg2 */
  [ "\x66\x81\xf0",       5, $reg1, [ $reg ] ], # /* xorw $imm16,%reg1 */
  [ "\x31\xc0",           2, $reg2, [ $reg ] ], # /* xorl %reg1,%reg2 */
  [ "\x81\xf0",           6, $reg1, [ $reg ] ], # /* xorl $imm32,%reg1 */
  [ "\xf6\xe0",           2, $reg1, [ $eax ] ], # /* mulb %reg1 */
  [ "\x66\xf7\xe0",       3, $reg1, [ $eax, $edx ] ], # /* mulw %reg1 */
  [ "\xf7\xe0",           2, $reg1, [ $eax, $edx ] ], # /* mull %reg1 */
  [ "\x20\xc0",           2, $reg2, [ $reg ] ], # /* andb %reg1,%reg2 */
  [ "\x80\xe0",           3, $reg1, [ $reg ] ], # /* andb $imm8,%reg1 */
  [ "\x66\x21\xc0",       3, $reg2, [ $reg ] ], # /* andw %reg1,%reg2 */
  [ "\x66\x81\xe0",       5, $reg1, [ $reg ] ], # /* andw $imm16,%reg1 */
  [ "\x21\xc0",           2, $reg2, [ $reg ] ], # /* andl %reg1,%reg2 */
  [ "\x81\xe0",           6, $reg1, [ $reg ] ], # /* andl $imm32,%reg1 */
  [ "\x08\xc0",           2, $reg2, [ $reg ] ], # /* orb %reg1,%reg2 */
  [ "\x80\xc8",           3, $reg1, [ $reg ] ], # /* orb $imm8,%reg1 */
  [ "\x0c",               2, $none, [ $eax ] ], # /* orb $imm8,%al */
  [ "\x66\x09\xc0",       3, $reg2, [ $reg ] ], # /* orw %reg1,%reg2 */
  [ "\x66\x81\xc8",       5, $reg1, [ $reg ] ], # /* orw $imm16,%reg1 */
  [ "\x66\x0d",           4, $none, [ $reg ] ], # /* orw $imm16,%ax */
  [ "\x09\xc0",           2, $reg2, [ $reg ] ], # /* orl %reg1,%reg2 */
  [ "\x81\xc8",           6, $reg1, [ $reg ] ], # /* orl $imm32,%reg1 */
  [ "\x0d",               5, $none, [ $eax ] ], # /* orl $imm32,%eax */
  [ "\x04",               2, $none, [ $eax ] ], # /* addb $imm8,%al */
  [ "\x80\xc0",           3, $reg1, [ $reg ] ], # /* addb $imm8,%reg1 */
  [ "\x66\x01\xc0",       3, $reg2, [ $reg ] ], # /* addw %reg1,%reg2 */
  [ "\x66\x81\xc0",       5, $reg1, [ $reg ] ], # /* addw $imm16,%reg1 */
  [ "\x66\x05",           4, $none, [ $eax ] ], # /* addw $imm16,%ax */
  [ "\x01\xc0",           2, $reg2, [ $reg ] ], # /* addl %reg1,%reg2 */
  [ "\x81\xc0",           6, $reg2, [ $reg ] ], # /* addl $imm32,%reg1 */
  [ "\x05",               5, $none, [ $eax ] ], # /* addl $imm32,%eax */
  [ "\x28\xc0",           2, $reg2, [ $reg ] ], # /* subb %reg1,%reg2 */
  [ "\x80\xe8",           3, $reg1, [ $reg ] ], # /* subb $imm8,%reg1 */
  [ "\x66\x29\xc0",       3, $reg2, [ $reg ] ], # /* subw %reg1,%reg2 */
  [ "\x66\x81\xe8",       5, $reg1, [ $reg ] ], # /* subw $imm16,%reg1 */
  [ "\x29\xc0",           2, $reg2, [ $reg ] ], # /* subl %reg1,%reg2 */
  [ "\x81\xe8",           6, $reg1, [ $reg ] ], # /* subl $imm32,%reg1 */
  [ "\xf6\xd0",           2, $reg1, [ $reg ] ], # /* notb %reg1 */
  [ "\x66\xf7\xd0",       3, $reg1, [ $reg ] ], # /* notw %reg1 */
  [ "\xf7\xd0",           2, $reg1, [ $reg ] ], # /* notl %reg1 */
  [ "\x84\xc0",           2, $reg2, [ ] ], # /* testb %reg1,%reg2 */
  [ "\xf6\xc0",           3, $reg1, [ ] ], # /* testb $imm8,%reg1 */
  [ "\xa8",               2, $none, [ ] ], # /* testb $imm8,%al */
  [ "\x66\x85\xc0",       3, $reg2, [ ] ], # /* testw %reg1,%reg2 */
  [ "\x66\xf7\xc0",       5, $reg1, [ ] ], # /* testw $imm16,%reg1 */
  [ "\x66\xa9",           4, $none, [ ] ], # /* testw $imm16,%ax */
  [ "\x85\xc0",           2, $reg2, [ ] ], # /* testl %reg1,%reg2 */
  [ "\xf7\xc0",           6, $reg1, [ ] ], # /* testl $imm32,%reg1 */
  [ "\xa9",               5, $none, [ ] ], # /* testl $imm32,%eax */
  [ "\x38\xc0",           2, $reg2, [ ] ], # /* cmpb %reg1,%reg2 */
  [ "\x3c",               2, $none, [ ] ], # /* cmpb $imm8,%al */
  [ "\x80\xf8",           3, $reg1, [ ] ], # /* cmpb $imm8,%reg1 */
  [ "\x66\x39\xc0",       3, $reg2, [ ] ], # /* cmpw %reg1,%reg2 */
  [ "\x66\x3d",           4, $none, [ ] ], # /* cmpw $imm16,%ax */
  [ "\x66\x81\xf8",       5, $reg1, [ ] ], # /* cmpw $imm16,%reg1 */
  [ "\x39\xc0",           2, $reg2, [ ] ], # /* cmpl %reg1,%reg2 */
  [ "\x3d",               5, $none, [ ] ], # /* cmpl $imm32,%eax */
  [ "\x81\xf8",           6, $reg1, [ ] ], # /* cmpl $imm32,%reg1 */
  [ "\xd4",               2, $none, [ $eax ] ], # /* aam $imm8 */
  [ "\xd5",               2, $none, [ $eax ] ], # /* aad $imm8 */
  [ "\xf5",               1, $none, [ ] ], # /* cmc */
  [ "\xf8",               1, $none, [ ] ], # /* clc */
  [ "\xf9",               1, $none, [ ] ], # /* stc */
  [ "\xfc",               1, $none, [ ] ], # /* cld */
  [ "\xfd",               1, $none, [ ] ], # /* std */
  [ "\x06",               1, $none, [ $esp ] ], # /* push %es */
  [ "\x0e",               1, $none, [ $esp ] ], # /* push %cs */
  [ "\x14",               2, $none, [ $eax ] ], # /* adc $imm8,%al */
  [ "\x66\x15",           4, $none, [ $eax ] ], # /* adc $imm16,%ax */
  [ "\x15",               5, $none, [ $eax ] ], # /* adc $imm32,%eax */
  [ "\x16",               1, $none, [ $esp ] ], # /* push %ss */
  [ "\x1c",               2, $none, [ $eax ] ], # /* sbbb $imm8,%al */
  [ "\x66\x1d",           4, $none, [ $eax ] ], # /* sbbw $imm16,%ax */
  [ "\x1d",               5, $none, [ $eax ] ], # /* sbbl $imm32,%eax */
  [ "\x80\xd8",           3, $reg1, [ $reg ] ], # /* sbbb $imm8,%reg1 */
  [ "\x66\x83\xd8",       4, $reg1, [ $reg ] ], # /* sbbw $imm8,%reg1 */
  [ "\x66\x81\xd8",       5, $reg1, [ $reg ] ], # /* sbbw $imm16,%reg1 */
  [ "\x83\xd8",           3, $reg1, [ $reg ] ], # /* sbbl $imm8,%reg1 */
  [ "\x81\xd8",           6, $reg1, [ $reg ] ], # /* sbbl $imm32,%reg1 */
  [ "\x1e",               1, $none, [ $esp ] ], # /* push %ds */

# added by spoon...
  # xchg eax, eax == 0x90 == nop... fancy
  [ "\x90",               1, $reg1, [ $eax, $reg ] ], # /* # xchg eax,reg1 */
  [ "\x99",               1, $none, [ $edx ] ], # /* # cdq */
  [ "\x37",               1, $none, [ $eax ] ], # /* # aaa */
  [ "\x3f",               1, $none, [ $eax ] ], # /* # aas */
  [ "\x27",               1, $none, [ $eax ] ], # /* # daa */
  [ "\x2f",               1, $none, [ $eax ] ], # /* # das */
  [ "\x98",               1, $none, [ $eax ] ], # /* # cwde */
  [ "\x9f",               1, $none, [ $eax ] ], # /* # lahf */
  [ "\xd6",               1, $none, [ $eax ] ], # /* # salc */
  [ "\x9b",               1, $none, [ ] ], # /* # wait */
  [ "\x58",               1, $reg1, [ $esp, $reg ] ], # /* # pop reg1 */
  [ "\x9c",               1, $none, [ $esp ] ], # /* # pushf */
  [ "\x60",               1, $none, [ $esp ] ], # /* # pusha */

# jmpy jmp jmp
  [ "\xeb",               2, $none, [ ], \&_InsHandlerJmp ], # jmp byte offset
  [ "\x70",               2, $none, [ ], \&_InsHandlerJmp ], # jo
  [ "\x71",               2, $none, [ ], \&_InsHandlerJmp ], # jno
  [ "\x72",               2, $none, [ ], \&_InsHandlerJmp ], # jc
  [ "\x73",               2, $none, [ ], \&_InsHandlerJmp ], # jnc
  [ "\x74",               2, $none, [ ], \&_InsHandlerJmp ], # jz
  [ "\x75",               2, $none, [ ], \&_InsHandlerJmp ], # jnz
  [ "\x76",               2, $none, [ ], \&_InsHandlerJmp ], # jna
  [ "\x77",               2, $none, [ ], \&_InsHandlerJmp ], # ja
  [ "\x78",               2, $none, [ ], \&_InsHandlerJmp ], # js
  [ "\x79",               2, $none, [ ], \&_InsHandlerJmp ], # jns
  [ "\x7a",               2, $none, [ ], \&_InsHandlerJmp ], # jpe
  [ "\x7b",               2, $none, [ ], \&_InsHandlerJmp ], # jpo
  [ "\x7c",               2, $none, [ ], \&_InsHandlerJmp ], # jl
  [ "\x7d",               2, $none, [ ], \&_InsHandlerJmp ], # jnl
  [ "\x7e",               2, $none, [ ], \&_InsHandlerJmp ], # jng
  [ "\x7f",               2, $none, [ ], \&_InsHandlerJmp ], # jg
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
  my $pos = $len - 1;

  while(1) {
    my $index = int(rand(@{$table}));
    
    # lie a bit, generate the first instruction, single byte only.
    next if(!$self->_CheckIns($index, $pos, $len - 1));

    my $code = $table->[$index]->[0];
    substr($data, $pos, 1, $self->_SetRegs(substr($code, -1, 1), $index));
    last;
  }

  # Now the first instruction is generated, all should be good...
  while($pos > 0) {
    my $index = int(rand(@{$table}));

    next if(!$self->_CheckIns($index, $pos, $len));

    my $code = $table->[$index]->[0];
    my $codeLen = length($code);
    my $insLen = $table->[$index]->[1];

    # Check to see if it's a one byte codelen type that wants SetRegs called
    if($self->_InsHandler(0, $index, $pos, $len, $data)) {
      $pos--;
      substr($data, $pos, 1, $self->_SetRegs(substr($code, -1, 1), $index));
      next;
    }

    # Check to see if the byte that already exists will make for a valid
    # ending byte to our current instruction
    next if(!$self->_InsHandler(1, $index, $pos, $len, $data));

    $pos -= $codeLen;
    substr($data, $pos, $codeLen, $code);
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


  my $type = $table->[$index]->[2];

  # instruction would run off the end
  return(0) if(($insLen - 1) > ($len - $pos));

  # instruction would run off the front
  return(0) if($codeLen > $pos);
  # test to see if the instruction always modifies a bad register.
  return(0) if($self->_SmashCheck($index));

  if($type == $reg2) {
    return($self->_CheckInsReg2($index, $pos, $len));
  }
  elsif($type == $reg1) {
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


  # Make sure the static portion of the instruction doesn't have bad bytes
  return(0) if(Pex::Text::BadCharCheck(
    $self->_BadChars,
    substr($code, $codeLen - 2, $codeLen - 1)
  ));

  # check to make sure that a generation is possible w/ current constraints
  return(0) if(!$self->_CheckReg2Possible(substr($code, -1, 1)));
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

  for(my $i = 0; $i < 8; $i++) {
    next if($self->_BadRegCheck($i));
    return(1) if($self->_CheckReg1Possible($byte + chr($i << 3)));
  }
  return(0);
}

# Make sure that given a byte for a single register instruction, there is a 
# generation possible.
sub _CheckReg1Possible {
  my $self = shift;
  my $byte = shift;

  my $badChars = $self->_BadChars;

  for(my $i = 0; $i < 8; $i++) {
    next if($self->_BadRegCheck($i));
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

  if($flags == $reg2) {
    my ($r1, $r2, $r) = (0, 0, 0);
    do {
      $r2 = int(rand(8));
      $r1 = int(rand(8));
      $r = $r2 << 3 + $r1;
    } while($self->_BadRegCheck($r1)
        || $self->_BadRegCheck($r2)
        || Pex::Text::BadCharCheck($byte | chr($r)));

    return($byte | chr($r));
  }

  elsif($flags == $reg1) {
    my $r = 0;
    do {
      $r = int(rand(8));
    } while($self->_BadRegCheck($r)
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

  if($flags == $reg2) {
    return(0) if(($byte & 0xc0) ne $ins);
    goto regcheck;
  }
  elsif($flags == $reg1) {
    return(0) if(($byte & 0xf8) ne $ins);
regcheck:
    return(0) if($self->_SmashCheckReg($index, $reg & 0x07));  
  }
  else {
    return(0) if($byte ne $ins);
  }

  return(1);
}

1;
