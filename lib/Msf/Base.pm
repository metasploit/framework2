##
#         Name: Base.pm
#       Author: spoonm <ninjatools [at] hush.com>
#      Version: $Revision$
#  Description: Parent class to all Msf bits.  Responsible for globally holding
#               the global and temporary environments, error and printing
#               methods, and other general methods useful to child classes.
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Msf::Base;
use strict;

use FindBin qw {$RealBin $RealScript};
use File::Spec::Functions;

# Load the core modules
use Msf::Encoder;
use Msf::Nop;
use Msf::EncodedPayload;
use Msf::Socket::Tcp;
use Msf::Socket::Udp;

use Pex::Text;

my $envDebug = 0;

sub Version {
  return("2.7");
}

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

# Print Function Overrides
sub _OverridePrint {
  my $self = shift;
  $Msf::Base::_OverridePrint = shift if(@_);
  return($Msf::Base::_OverridePrint);
}
sub _OverridePrintStderr {
  my $self = shift;
  $Msf::Base::_OverridePrintStderr = shift if(@_);
  return($Msf::Base::_OverridePrintStderr);
}
sub _OverridePrintLine {
  my $self = shift;
  $Msf::Base::_OverridePrintLine = shift if(@_);
  return($Msf::Base::_OverridePrintLine);
}
sub _OverridePrintDebug {
  my $self = shift;
  $Msf::Base::_OverridePrintDebug = shift if(@_);
  return($Msf::Base::_OverridePrintDebug);
}
sub _OverridePrintDebugLine {
  my $self = shift;
  $Msf::Base::_OverridePrintDebugLine = shift if(@_);
  return($Msf::Base::_OverridePrintDebugLine);
}
sub _OverrideError {
  my $self = shift;
  $Msf::Base::_OverrideError = shift if(@_);
  return($Msf::Base::_OverrideError);
}
sub _OverrideErrorLine {
  my $self = shift;
  $Msf::Base::_OverrideErrorLine = shift if(@_);
  return($Msf::Base::_OverrideErrorLine);
}


sub GetEnv {
  my $self = shift;
  my $key = shift;
  my @envs = ($self->GetTempEnv, $self->GetGlobalEnv);
  print join(' ', caller()) if($envDebug >= 3);
# fixme more than two envs...
  return($self->MergeHash($envs[0], $envs[1])) if(!defined($key));

  foreach my $env (@envs) {
    if(exists($env->{$key})) {
      print "Get $key => " . $env->{$key} . "\n" if($envDebug);
      return($env->{$key});
    }
    
    # Case insensitive matching for the newbies/typos
    foreach my $ekey (keys(%{$env})) {
      if (lc($ekey) eq lc($key)) {
        print STDERR "[*] WARNING: the correct case of the '$ekey' variable is '$key'\n";
        $env->{$key} = $env->{$ekey};
        delete($env->{$ekey});
        return $env->{$key};
      }
    }
  }

  
  return;
}


# Global Environment
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
      if ($pairs[$i] =~ /^socks/) {
          Pex::Socket::socks_setup($pairs[$i], $pairs[$i + 1]);
      }
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

# Temporary Environment
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
  print "UnsetTempEnv $key\n" if($envDebug);
  if(!defined($key)) {
    $self->_TempEnv({ });
  }
  else {
    delete($self->_TempEnv->{$key});
  }
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

# fixme LoadTempEnv doesn't make a copy, so you are modifing the saved copy...
sub LoadTempEnv {
  my $self = shift;
  my $name = shift;
  print "LoadTempEnv $name\n" if($envDebug);
  $self->_TempEnv($self->_TempEnvs->{$name});
  return($self->_TempEnv);
}

# Error Code
sub IsError {
  my $self = shift;
  return(defined($self->GetError));
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
  return(0) if(!$self->IsError);
  
  if ($error) {
  	$self->PrintLine("Error: $error");
  }
  
  $self->ClearError;
  return(1);
}

# Print Foo
sub Print {
  my $self = shift;
  my @args = @_;
  if(defined($self->_OverridePrint)) {
    return(&{$self->_OverridePrint}($self, @args));
  }
  @args[0] =~ s/\e/\[ESC\]/g;
  print STDOUT @args;
}

sub PrintStderr {
  my $self = shift;
  my @args = @_;
  if(defined($self->_OverridePrintStderr)) {
    return(&{$self->_OverridePrintStderr}($self, @args));
  }
  @args[0] =~ s/\e/\[ESC\]/g;
  print STDERR @args;
}

sub PrintLine {
  my $self = shift;
  if(defined($self->_OverridePrintLine)) {
    return(&{$self->_OverridePrintLine}($self, @_));
  }
  $self->Print(@_, "\n");
}

sub PrintDebug {
  my $self = shift;
  my $level = shift;
  if(defined($self->_OverridePrintDebug)) {
    return(&{$self->_OverridePrintDebug}($self, $level. @_));
  }
  $self->PrintStderr(@_) if($self->DebugLevel >= $level);
}
sub PrintDebugLine {
  my $self = shift;
  my $level = shift;
  if(defined($self->_OverridePrintDebugLine)) {
    return(&{$self->_OverridePrintDebugLine}($self, $level, @_));
  }
  $self->PrintDebug($level, @_, "\n");
}

sub Error {
  my $self = shift;
  if(defined($self->_OverrideError)) {
    return(&{$self->_OverrideError}($self, @_));
  }
  $self->Print(@_);
}

sub ErrorLine {
  my $self = shift;
  if(defined($self->_OverrideErrorLine)) {
    return(&{$self->_OverrideErrorLine}($self, @_));
  }
  $self->PrintLine(@_);
}

# Other stuff
sub DebugLevel {
  my $self = shift;
  return($self->GetEnv('DebugLevel'));
}

sub MergeHash {
  my $self = shift;
  my $hash1 = shift || { };
  my $hash2 = shift || { };
  my %hash = %{$hash1};
  foreach (keys(%{$hash2})) {
    if(!defined($hash1->{$_})) {
      $hash{$_} = $hash2->{$_};
    }
  }
  return(\%hash);
}

sub MergeHashRec {
  my $self = shift;
  my $hash1 = shift || { };
  my $hash2 = shift || { };
  my %hash = %{$hash1};
  foreach (keys(%{$hash2})) {
    if(!defined($hash1->{$_})) {
      $hash{$_} = $hash2->{$_};
    }
    # recurse if both are hash refs
    elsif(ref($hash1->{$_}) eq 'HASH' && ref($hash2->{$_}) eq 'HASH') {
      $hash{$_} = $self->MergeHashRec($hash1->{$_}, $hash2->{$_});
    }
    # recurse if both are array refs
    elsif(ref($hash1->{$_}) eq 'ARRAY' && ref($hash2->{$_}) eq 'ARRAY') {
      my @res = @{$hash1->{$_}};
      foreach my $kval (@{$hash2->{$_}}) {
        if(ref($kval) || !Pex::Utils::ArrayContains(\@res, [ $kval ])) {
          push(@res, $kval);
        }
      }
      $hash{$_} = [ @res ];
    }
  }
  return(\%hash);
}

sub SelfName {
  my $self = shift;
  return($self->ModuleName($self));
}

sub SelfEndName {
  my $self = shift;
  return($self->ModuleEndName($self));
}

sub ModuleName {
  my $self = shift;
  my $module = shift;
  my ($name) = split('=HASH', $module);
  return($name);
}

sub ModuleEndName {
  my $self = shift;
  my $module = shift;
  my $name = $self->ModuleName($module);
  my @parts = split('::', $name);
  return($parts[-1]);
}

sub ScriptPath {
  my $self = shift;
  return "$RealBin/$RealScript";
}

sub ScriptBase {
  my $Self = shift;
  return $RealBin;
}

1;
