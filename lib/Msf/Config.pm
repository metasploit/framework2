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
  my ($globalEnv, $tempEnvs) = $self->ReadConfig($configFile);
  $self->SetGlobalEnv(%{$self->MergeHash($globalEnv, $defaults)});

  $self->SaveTempEnv('_Save');
  $self->UnsetTempEnv;
  foreach my $tempEnv (keys %{$tempEnvs}) {
    $self->SetTempEnv(%{$tempEnvs->{$tempEnv}});
    $self->SaveTempEnv($tempEnv);
    $self->UnsetTempEnv;
  }
  $self->LoadTempEnv('_Save');
  $self->DeleteTempEnv('_Save');
}
sub SaveConfig {
  my $self = shift;
  my $configFile = shift;
  $self->WriteConfig($configFile, $self->GetEnv);
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
#fixme needs to be updated for temp envs
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
