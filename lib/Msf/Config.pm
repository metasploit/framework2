package Msf::Config;
use strict;
use base 'Msf::Base';
use File::Spec::Functions;
use File::Basename;

my $defaults = {
  'Encoder' => 'Msf::Encoder::Pex',
  'Nop'     => 'Msf::Nop::Pex',
  'DebugLevel' => 0,
  'Logging' => 'Enabled',
};

sub PopulateConfig {
  my $self = shift;
  my $configFile = shift;
  my ($globalEnv, $tempEnvs) = $self->ReadConfig($configFile);
  $self->SetGlobalEnv(%{$self->MergeHash($globalEnv, $defaults)});

  foreach my $tempEnv (keys %{$tempEnvs}) {
    $self->SetSavedTempEnv($tempEnv, %{$tempEnvs->{$tempEnv}});
  }
}

sub SaveConfig {
  my $self = shift;
  my $configFile = shift;
  $self->WriteConfig($configFile, $self->GetGlobalEnv, $self->GetTempEnvs);
}

sub ReadConfig {
  my $self = shift;
  my $configFile = shift;
  my $globalEnv = { };
  my $tempEnvs = { };
  my $env = $globalEnv;
  open(INFILE, "<$configFile") or return($globalEnv, $tempEnvs);
  while(<INFILE>) {
    s/\r//g;
    chomp;
    next if(/^\w*#/);
    if(/^(.*?)=(.*)/) {
      $env->{$1} = $2;
    }
    elsif(/^(.*?):/) {
      $tempEnvs->{$1} = { };
      $env = $tempEnvs->{$1};
    }
  }
  close(INFILE);
  return($globalEnv, $tempEnvs);
}

sub WriteConfig {
  my $self = shift;
  my $configFile = shift;
  my $globalEnv = shift;
  my $tempEnvs = shift;

  open(OUTFILE, ">$configFile") or return;
  foreach (sort(keys(%{$globalEnv}))) {
    print OUTFILE "$_=" . $globalEnv->{$_} . "\n";
  }
  foreach my $tempEnv (sort(keys(%{$tempEnvs}))) {
    print OUTFILE "\n$tempEnv:\n";
    foreach (sort(keys(%{$tempEnvs->{$tempEnv}}))) {
      print OUTFILE "$_=" . $tempEnvs->{$tempEnv}->{$_} . "\n";
    }
  }
  close(OUTFILE);
}

1;
