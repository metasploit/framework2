package Pex::Nasm::Nasm;
use strict;
use IPC::Open2;

sub AsmFile {
  my $package = shift;
  my $filename = shift;
  my $opts = @_ ? shift : '';
  my ($read, $write);
  my $pid = open2($read, $write, 'nasm', '-o', '/dev/stdout', $opts, $filename);
  local $/;
  my $out = <$read>;
  waitpid($pid, 0);
  close($read);
  close($write);
  return($out);
}

sub AsmData {
  my $package = shift;
  my $data = shift;
  my $opts = @_ ? shift : '';
  my ($read, $write);
  local $/;
  open(FUCK, '>/tmp/annoying');
  print FUCK $data;
  close(FUCK);
  my $pid = open2($read, $write, 'nasm', '-o', '/dev/stdout', $opts, '/tmp/annoying');
  my $out = <$read>;
  waitpid($pid, 0);
  close($read);
  unlink("/tmp/annoying");
  return($out);
}

1;
