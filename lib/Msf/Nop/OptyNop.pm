#!/usr/bin/perl
package Msf::Nop::OptyNop;
use strict;
use base 'Msf::Nop';

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
];

# XXX
# there is kinda a bug maybe to be fixed... last 2 bytes are always single
# byte nops, and they don't have to be... it's the way the pos stuff is done

sub _GenerateSlide {
  my $self = shift;
  my $len = shift;

  my $data = "\x00" x $len;
  my $pos = $len - 1;

  my $badChars = $self->_BadChars;

  while($pos >= 0) {
    my $index = int(rand(@{$table}));

    next if($self->_SmashCheck($index));

    my $code = $table->[$index]->[0];
    my $codeLen = length($code);
    my $insLen = $table->[$index]->[1];

    next if(Pex::Text::BadCharCheck($badChars, $code));

recheck:
    # instruction would run off the end
    next if($insLen > ($len - $pos));

    
    # instruction would run off the front
    next if(($codeLen - 1) > $pos);

    if($codeLen == 1) {
      if(substr($data, $pos, 1) ne "\x00") {
        $pos--;
        goto recheck;
      }

      substr($data, $pos, 1, $self->_SetRegs(substr($code, -1, 1), $index));
      next;
    }

    $codeLen--;

    next if(!$self->_ValidReg(
      substr($data, $pos, 1),
      substr($table->[$index]->[0], $codeLen, 1),
      $index)
    );

    $pos -= $codeLen;
    substr($data, $pos, $codeLen + 1, $table->[$index]->[0]);
  }

  return($data);
}

sub _BadRegs {
  return([$ebp, $esp]);
#  return([ ]);
}

sub _BadChars {
  return('');
}

sub _SmashCheck {
  my $self = shift;
  my $index = shift;

  foreach my $r (@{$table->[$index]->[3]}) {
    return(1) if($self->_BadRegCheck($r));
  }
  return(0);
}
sub _SmashCheckReg {
  my $self = shift;
  my $index = shift;
  my $rreg = shift;

  foreach my $r (@{$table->[$index]->[3]}) {
    return(1) if($r == $reg && $self->_BadRegCheck($rreg));
  }
  return(0);
}

sub _BadRegCheck {
  my $self = shift;
  my $r = shift;

  my $badRegs = $self->_BadRegs;
  foreach my $breg (@{$badRegs}) {
    return(1) if($r == $breg);
  }
  return(0);
}

sub _SetRegs {
  my $self = shift;
  my $byte = shift;
  my $index = shift;

  my $flags = $table->[$index]->[2];
  my $r = 0;
  if($flags == $reg2) {
    $r = int(rand(8)) << 3;
    $flags = $reg1;
  }

  if($flags == $reg1) {
    my $rr;
    do {
      $rr = int(rand(8));
    } while($self->_BadRegCheck($rr));

    $r += $rr;
  }

  return($byte | chr($r));
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
