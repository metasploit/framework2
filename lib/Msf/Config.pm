package Msf::Config;
use strict;
use base 'Msf::Base';
use File::Spec::Functions;
use File::Basename;

my $defaults = {
  'Encoder' => 'Msf::Encoder::Pex',
  'Nop'     => 'Msf::Nop::Pex',
};

sub PopulateConfig {
  my $self = shift;
  my $configFile = shift;
  $self->SetEnv(%{$self->MergeHash($self->ReadConfig($configFile), $defaults)});
}
sub SaveConfig {
  my $self = shift;
  my $configFile = shift;
  $self->WriteConfig($configFile, $self->GetEnv);
}

sub ReadConfig {
  my $self = shift;
  my $configFile = shift;
  my $config = { };
  open(INFILE, "<$configFile") or return($config);
  while(<INFILE>) {
    s/\r//g;
    chomp;
    next if(/^\w*#/);
    if(/^(.*?)=(.*)/) {
      $config->{$1} = $2;
    }
  }
  close(INFILE);
  return($config);
}
sub WriteConfig {
  my $self = shift;
  my $configFile = shift;
  my %config = @_;
  open(OUTFILE, ">$configFile") or return;
  foreach (keys(%config)) {
    print OUTFILE "$_=$config{$_}\n";
  }
  close(OUTFILE);
}

1;
