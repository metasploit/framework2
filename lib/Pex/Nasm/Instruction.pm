package Pex::Nasm::Instruction;
use strict;

my $regs = {
  'eax' => [ 'eax', 'ax', 'ah', 'al' ],
  'ebx' => [ 'ebx', 'bx', 'bh', 'bl' ],
  'ecx' => [ 'ecx', 'cx', 'ch', 'cl' ],
  'edx' => [ 'edx', 'dx', 'dh', 'dl' ],
  'esi' => [ 'esi', 'si' ],
  'edi' => [ 'edi', 'di' ],
  'ebp' => [ 'ebp', 'bp' ],
  'eip' => [ 'eip', 'ip' ],
  'esp' => [ 'esp', 'sp' ],
};

sub new {
  my $class = shift;
  my $self = bless({ }, $class);
  $self->ParseInstruction(shift) if(@_);
  $self->Offset(shift) if(@_);
  $self->RawData(shift) if(@_);
  return($self);
}

sub Opcode {
  my $self = shift;
  $self->{'Opcode'} = shift if(@_);
  return($self->{'Opcode'});
}
sub Modifier {
  my $self = shift;
  $self->{'Modifier'} = shift if(@_);
  return($self->{'Modifier'});
}
sub RawData {
  my $self = shift;
  $self->{'RawData'} = shift if(@_);
  return($self->{'RawData'});
}
sub TextInstruction {
  my $self = shift;
  $self->{'TextInstruction'} = shift if(@_);
  return($self->{'TextInstruction'});
}
sub Offset {
  my $self = shift;
  $self->{'Offset'} = shift if(@_);
  return($self->{'Offset'});
}
sub Operands {
  my $self = shift;
  $self->{'Operands'} = shift if(@_);
  $self->{'Operands'} = [ ] if(ref($self->{'Operands'}) ne 'ARRAY');
  return($self->{'Operands'});
}
sub AddOperand {
  my $self = shift;
  my $operand = shift;
  push(@{$self->Operands}, $operand);
}

sub ParseInstruction {
  my $self = shift;
  my $ins = shift;
  my $info = { };
  $self->TextInstruction($ins);
#  print "++$ins++";
  $ins =~ /^\s*(\S+)(?:\s+(.*))?/;
  my $opcode = $1;
  my $rest = $2;
  $self->Opcode($opcode);
#  print "--$opcode--$rest--";
  my @operands = split(',', $rest);
  foreach my $operand (@operands) {
    my @modifier = split(' ', $operand);
    if(@modifier >= 2) {
      $self->Modifier($modifier[0]);
    }
    $self->AddOperand($modifier[-1]);
  }
}

#fixme
sub Equals {
  my $self = shift;
  my $instruction = shift;
  return($instruction->TextInstruction eq $self->TextInstruction);
}

1;
