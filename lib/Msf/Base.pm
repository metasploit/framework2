package Msf::Base;
use strict;

use FindBin qw {$Bin $RealBin $Script $RealScript};

#fixme Temporary hack
use Msf::Encoder;
use Msf::Nop;
use Msf::EncodedPayload;
use File::Spec::Functions;

my $envDebug = 0;

sub new {
  my $class = shift;
  my $hash = @_ ? shift : { };
  my $self = bless($hash, $class);
  return($self);
}
sub _Env {
  my $self = shift;
  $Msf::Base::Env = shift if(@_);
  $Msf::Base::Env = { } if(!defined($Msf::Base::Env));
  return($Msf::Base::Env);
}
sub _TempEnv {
  my $self = shift;
  $Msf::Base::TempEnv = shift if(@_);
  $Msf::Base::TempEnv = { } if(!defined($Msf::Base::TempEnv));
  return($Msf::Base::TempEnv);
}
sub _TempEnvs {
  my $self = shift;
  $Msf::Base::TempEnvs = shift if(@_);
  $Msf::Base::TempEnvs = { } if(!defined($Msf::Base::TempEnvs));
  return($Msf::Base::TempEnvs);
}
sub _Error {
  my $self = shift;
  $self->{'Error'} = shift if(@_);
  return($self->{'Error'});
}

sub GetEnv {
  my $self = shift;
  my $key = shift;
  my @envs = ($self->GetTempEnv, $self->GetGlobalEnv);
  print join(' ', caller()) if($envDebug >= 3);
  foreach my $env (@envs) {
    if(exists($env->{$key})) {
      print "Get $key => " . $env->{$key} . "\n" if($envDebug);
      return($env->{$key});
    }
  }
# fixme more than two envs...
  return($self->MergeHash($envs[0], $envs[1]));
}

# fixme SetEnv...
# the cli wont work until this does, setting Temp
#sub SetEnv {
#  my $self = shift;
#  my $key = shift;
#  my $val = shift;
#  return $self->SetTempEnv($key, $val);
#}


sub GetGlobalEnv {
  my $self = shift;
  my $key = shift;
  my $env = $self->_Env;
  print join(' ', caller()) if($envDebug >= 3);
  if(defined($key)) {
    print "GetGlobal $key => " . $env->{$key} . "\n" if($envDebug);
    return($env->{$key});
  }

  return($env);
}

sub SetGlobalEnv {
  my $self = shift;
  my @pairs = @_;

  my $env = $self->_Env;

  for(my $i = 0; $i < @pairs; $i += 2) {
    print "SetGlobal $pairs[$i] => " . $pairs[$i + 1] . "\n" if($envDebug);
    $env->{$pairs[$i]} = $pairs[$i + 1];
  }
  return($env);
}

sub UnsetGlobalEnv {
  my $self = shift;
  my $key = shift;
  if(!defined($key)) {
    $self->_Env({ });
  }
  else {
    delete($self->_Env->{$key});
  }
}

sub GetTempEnv {
  my $self = shift;
  my $key = shift;
  my $env = $self->_TempEnv;
  if(defined($key)) {
    print "TempGet $key => " . $env->{$key} . "\n" if($envDebug);
    return($env->{$key});
  }
  return($env);
}

sub SetTempEnv {
  my $self = shift;
  my @pairs = @_;

  my $env = $self->_TempEnv;

  for(my $i = 0; $i < @pairs; $i += 2) {
    print "TempSet $pairs[$i] => " . $pairs[$i + 1] . "\n" if($envDebug);
    $env->{$pairs[$i]} = $pairs[$i + 1];
  }
  return($env);
}

sub GetSavedTempEnv {
  my $self = shift;
  my $envName = shift;
  my $key = shift;
  my $env = $self->_TempEnvs->{$envName};
  return if(!defined($env));
  if(defined($key)) {
    print "TempGet $key => " . $env->{$key} . "\n" if($envDebug);
    return($env->{$key});
  }
  return($env);
}

sub SetSavedTempEnv {
  my $self = shift;
  my $envName = shift;
  my @pairs = @_;

  # Create it if it doesn't exist
  $self->_TempEnvs->{$envName} = { } if(!defined($self->_TempEnvs->{$envName}));
  my $env = $self->_TempEnvs->{$envName};

  for(my $i = 0; $i < @pairs; $i += 2) {
    print "TempSet $pairs[$i] => " . $pairs[$i + 1] . "\n" if($envDebug);
    $env->{$pairs[$i]} = $pairs[$i + 1];
  }
  return($env);
}


sub UnsetTempEnv {
  my $self = shift;
  my $key = shift;
  print "UnsetTempEnv $key\n" if($envDebug);
  if(!defined($key)) {
    $self->_TempEnv({ });
  }
  else {
    delete($self->_TempEnv->{$key});
  }
}

sub DeleteTempEnv {
  my $self = shift;
  my $key = shift;
  if(!defined($key)) {
    $self->_TempEnvs({ });
    $self->_TempEnv({ });
  }
  else {
    delete($self->_TempEnvs->{$key});
  }
}

sub GetTempEnvs {
  my $self = shift;
  return($self->_TempEnvs);
}

sub SaveTempEnv {
  my $self = shift;
  my $name = shift;
  print "SaveTempEnv $name\n" if($envDebug);
  my %copy = %{$self->_TempEnv};
  $self->_TempEnvs->{$name} = \%copy;
}

sub LoadTempEnv {
  my $self = shift;
  my $name = shift;
  print "LoadTempEnv $name\n" if($envDebug);
  $self->_TempEnv($self->_TempEnvs->{$name});
  return($self->_TempEnv);
}

sub GetError {
  my $self = shift;
  return($self->_Error);
}
sub SetError {
  my $self = shift;
  my $error = shift;
  $self->_Error($error);
  return($error);
}
sub ClearError {
  my $self = shift;
  $self->_Error(undef);
}

sub PrintError {
  my $self = shift;
  my $error = $self->_Error;

  if(! defined($error)) {
    return(0);
  }
  
  $self->PrintLine('Error: ', $error);
  $self->ClearError;
  return(1);
}

sub DebugLevel {
  my $self = shift;
  return($self->GetEnv('DebugLevel'));
}

sub PrintDebug {
  my $self = shift;
  my $level = shift;
  if(defined($self->{'PrintDebug'})) {
    return(&{$self->{'PrintDebug'}}($self, @_));
  }
  $self->Print(@_) if($self->DebugLevel >= $level);
}
sub PrintDebugLine {
  my $self = shift;
  my $level = shift;
  if(defined($self->{'PrintDebugLine'})) {
    return(&{$self->{'PrintDebugLine'}}($self, @_));
  }
  $self->PrintLine(@_) if($self->DebugLevel >= $level);
}

sub Error {
  my $self = shift;
  $self->PrintLine(@_);
}

sub PrintLine {
  my $self = shift;
  if(defined($self->{'PrintLine'})) {
    return(&{$self->{'PrintLine'}}($self, @_));
  }
  $self->Print(@_, "\n");
}

sub Print {
  my $self = shift;
  if(defined($self->{'Print'})) {
    return(&{$self->{'Print'}}($self, @_));
  }
  print STDOUT @_;
}

sub MergeHash {
  my $self = shift;
  my $hash1 = shift;
  my $hash2 = shift;
  foreach (keys(%$hash2)) {
    $hash1->{$_} = $hash2->{$_} if(!defined($hash1->{$_}));
  }
  return($hash1);
}

sub SelfName {
  my $self = shift;
  my ($name) = split('=HASH', $self);
  return($name);
}

sub ScriptPath {
  my $self = shift;
  return "$Bin/$Script";
}

sub ScriptBase {
  my $Self = shift;
  return $Bin;
}

sub FatalError {
  my $self = shift;
  my $error = shift;
  $self->SetError($error);
  $self->PrintError;
  exit(1);
}

1;
