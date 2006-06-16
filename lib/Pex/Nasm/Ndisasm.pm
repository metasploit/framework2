package Pex::Nasm::Ndisasm;
use strict;
use IPC::Open2;
use Pex::Nasm::Instruction;

sub DisasFile {
  my $package = shift;
  my $filename = shift;
  my $opts = @_ ? shift : '-u';
  my ($read, $write);
  my $pid = open2($read, $write, 'ndisasm', $opts, $filename);
  local $/;
  my $out = <$read>;
  waitpid($pid, 0);
  return($out);
}

sub DisasData {
  my $package = shift;
  my $data = shift;
  my $opts = @_ ? shift : '-u';
  my ($read, $write);
  my $pid = open2($read, $write, 'ndisasm', $opts, '-');
  local $/;
  print $write $data;
  close($write);
  my $out = <$read>;
  waitpid($pid, 0);
  close($read);
  return($out);
}

sub ParseOutput {
  my $package = shift;
  my $output = shift;
  my $inss = [ ];
  foreach my $line (split("\n", $output)) {
    if($line =~ /^(\w+)\s+(\w+)\s+(.*)$/) {
      my $index = hex($1);
      my $data = $2;
      my $ins = $3;
      $data = pack('H*', $data);
      push(@{$inss}, Pex::Nasm::Instruction->new($ins, $index, $data));
    }
  }
  return($inss);
}

1;
