package Msf::Base;
use strict;
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
  $self->{'Error'};
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
  return($Msf::Base::TempEnv);
}
sub _Error {
  my $self = shift;
  $self->{'Error'} = shift if(@_);
  return($self->{'Error'});
}

sub GetEnv {
  my $self = shift;
  my $key = shift;
  my $env = $self->_Env;
  print join(' ', caller()) if($envDebug >= 3);
  if(defined($key)) {
    print "Get $key => " . $env->{$key} . "\n" if($envDebug);
    return($env->{$key});
  }

  return($env);
}

sub SetEnv {
  my $self = shift;
  my @pairs = @_;

  my $env = $self->_Env;

  for(my $i = 0; $i < @pairs; $i += 2) {
    print "Set $pairs[$i] => " . $pairs[$i + 1] . "\n" if($envDebug);
    $env->{$pairs[$i]} = $pairs[$i + 1];
  }
  return($env);
}

sub UnsetEnv {
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

sub UnsetTempEnv {
  my $self = shift;
  my $key = shift;
  if(!defined($key)) {
    $self->_TempEnv({ });
  }
  else {
    delete($self->_TempEnv->{$key});
  }
}

sub GetTempEnvs {
  my $self = shift;
  return($self->_TempEnvs);
}

sub SaveTempEnv {
  my $self = shift;
  my $name = shift;
  $self->_TempEnvs->{$name} = $self->_TempEnv;
}

sub LoadTempEnv {
  my $self = shift;
  my $name = shift;
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
  return(File::Spec::Functions::rel2abs($0));
}

sub FatalError {
  my $self = shift;
  my $error = shift;
  $self->SetError($error);
  $self->PrintError;
  exit(1);
}


1;
