package Msf::Module;
use strict;
use base 'Msf::Base';
use Socket;

sub new {
  my $class = shift;
  my $hash = @_ ? shift : { };
  my $self = bless($hash, $class);

# We don't need this anymore
# use _Info and _Advanced, they will set themselves in undefined
  # Make sure Info and Defaults always exists
  # Makes life easier checking elsewhere
#  if(!defined($self->{'Info'})) {
#    $self->PrintDebugLine(4, "$self: No Info hash, setting to { }");
#    $self->{'Info'} = { };
#  }
#  if(!defined($self->{'Advanced'})) {
#    $self->PrintDebugLine(4, "$self: No Advanced hash, setting to { }");
#    $self->{'Advanced'} = { };
#  }
  return($self);
}

# Internal accessors/mutators
sub _Info {
  my $self = shift;
  $self->{'Info'} = { } if(!defined($self->{'Info'}));
  $self->{'Info'} = shift if(@_);
  return($self->{'Info'});
}
sub _Advanced {
  my $self = shift;
  $self->{'Advanced'} = { } if(!defined($self->{'Advanced'}));
  $self->{'Advanced'} = shift if(@_);
  return($self->{'Advanced'});
}

sub SetDefaults {
  my $self = shift;
  my $hash = shift;
  $self->MergeHash($self->_Info, $hash);
}


# Generic

sub Name        { my $self = shift; return $self->_Info->{'Name'}; }
sub Version     { my $self = shift; return $self->_Info->{'Version'}; }
sub Author      { my $self = shift; return $self->_Info->{'Author'}; }
sub Arch        { my $self = shift; return $self->_Info->{'Arch'}; }
sub OS          { my $self = shift; return $self->_Info->{'OS'}; }
sub Keys        { my $self = shift; return $self->_Info->{'Keys'}; }
sub Priv        { my $self = shift; return $self->_Info->{'Priv'}; }
sub UserOpts    { my $self = shift; return $self->_Info->{'UserOpts'}; }
sub Refs        { my $self = shift; return $self->_Info->{'Refs'}; }
sub Description { my $self = shift; return $self->_Info->{'Description'}; }


#fixme
# Used?
sub AutoOpts    { my $self = shift; return $self->_Info->{'AutoOpts'}; }

# Exploit Specific (move to Msf::Exploit?)
sub Payload     { my $self = shift; return $self->_Info->{'Payload'}; }

# Payload Specific (move to Msf::Payload?)
sub Type        { my $self = shift; return $self->_Info->{'Type'}; }

sub Validate {
  my $self = shift;
  my $userOpts = $self->UserOpts;

  foreach my $key (keys(%{$userOpts})) {
    my ($reqd, $type, $desc, $dflt) = @{$userOpts->{$key}};
    my $value = $self->GetVar($key);

    if(!defined($value) && $reqd) {
      $self->SetError("Missing required option: $key");
      return;
    }
    elsif(!defined($value)) {
      # option is not required, set it to the default
      if (defined($dflt)) { $self->SetVar($key, $dflt) }
    }
    elsif(uc($type) eq 'ADDR') {
      my $addr = gethostbyname($value);
      if(!$addr) {
        $self->SetError("Invalid address $value for $key");
        return;
      }
      # replace a hostname with an IP address
      $self->SetVar($key, inet_ntoa($addr));
    }
    elsif(uc($type) eq 'PORT') {
      if($value < 1 || $value > 65535) {
        $self->SetError("Invalid port $value for $key");
        return;
      }
    }
    elsif(uc($type) eq 'BOOL') {
      if($value !~ /^(y|n|t|f|0|1)$/i) {
        $self->SetError("Invalid boolean $value for $key");
        return;
      }
    }
    elsif(uc($type) eq 'PATH') {
      if(! -r $value) {
        $self->SetError("Invalid path $value for $key");
        return;
      }
    }
    elsif(uc($type) eq 'HEX') {
#fixme better hex check?
      if($value !~ /^[0-9a-f]+$/i && $value !~ /^0x[0-9a-f]+$/i) {
        $self->SetError("Invalid hex $value for $key");
        return;
      }
      # replace hex with int value
      $self->SetVar($key, hex($value));
    }
  }
  return(1);
}

# Pecking order:
# 1) KEY in TempEnv
# 2) KEY in Env
# 3) SelfName::KEY in Env
# 4) KEY in Advanced
# 5) KEY in UserOpts
sub GetVar {
  my $self = shift;
  my $key = shift;
  my $val;

  $val = $self->GetTempEnv($key);
  return($val) if(defined($val));
  $val = $self->GetGlobalEnv($key);
  return($val) if(defined($val));
  $val = $self->GetGlobalEnv($self->SelfName . '::' . $key);
  return($val) if(defined($val));
  $val = $self->GetAdvancedValue($key);
  return($val) if(defined($val));
  $val = $self->GetUserOptsDefault($key);
  return($val);
}

sub SetVar {
  my $self = shift;
  my $key = shift;
  my $val = shift;

  return($self->SetTempEnv($key, $val)) if(defined($self->GetTempEnv($key)));
  return($self->SetGlobalEnv($key, $val)) if(defined($self->GetGlobalEnv($key)));
  return($self->SetGlobalEnv($self->SelfName . '::' . $key, $val)) if(defined($self->GetGlobalEnv($self->SelfName . '::' . $key)));
  return($self->SetAdvancedValue($key, $val)) if(defined($self->GetAdvanced($key)));
  # Even thought it was is in UserOpts, we just mask it in Advanced
  return($self->SetAdvancedValue($key, $val)) if(defined($self->GetUserOptsDefault($key)));
  return;
}


# This will not look for $key in the global environment
sub GetLocal {
  my $self = shift;
  my $key = shift;
  my $val;

  $val = $self->GetTempEnv($key);
  return($val) if(defined($val));
  $val = $self->GetGlobalEnv($self->SelfName . '::' . $key);
  return($val) if(defined($val));
  $val = $self->GetAdvancedValue($key);
  return($val) if(defined($val));
  $val = $self->GetUserOptsDefault($key);
  return($val);
}

sub SetLocal {
  my $self = shift;
  my $key = shift;
  my $val = shift;

  return($self->SetTempEnv($key, $val)) if(defined($self->GetTempEnv($key)));
  return($self->SetGlobalEnv($self->SelfName . '::' . $key, $val)) if(defined($self->GetGlobalEnv($self->SelfName . '::' . $key)));
  return($self->SetAdvancedValue($key, $val)) if(defined($self->GetAdvanced($key)));
  # Even thought it was is in UserOpts, we just mask it in Advanced
  return($self->SetAdvancedValue($key, $val)) if(defined($self->GetUserOptsDefault($key)));
  return;
}

sub Advanced {
  my $self = shift;
  return($self->_Advanced);
}

sub GetAdvanced {
  my $self = shift;
  my $key = shift;
  return($self->_Advanced->{$key});
}

sub GetAdvancedValue {
  my $self = shift;
  my $key = shift;

#fixme why was this an issue? can't remember
  # Incase we get called with our scope prepended.
  my $removeChunk = $self->SelfName . '::';
  my $find = index($key, $removeChunk);
  substr($key, $find, length($removeChunk), '') if($find != -1);
  return if(!defined($self->_Advanced->{$key}));
  return($self->_Advanced->{$key}->[0]);
}

sub SetAdvanced {
  my $self = shift;
  my $key = shift;
  my $val = shift;
  return($self->_Advanced->{$key} = $val);
}

sub SetAdvancedValue {
  my $self = shift;
  my $key = shift;
  my $val = shift;
  $self->_Advanced->{$key} = [undef, undef] if(!defined($self->_Advanced->{$key}));
  return($self->_Advanced->{$key}->[0] = $val);
}

# UserOpts hash
sub GetUserOpts {
  my $self = shift;
  my $key = shift;
  my $userOpts = $self->UserOpts;
  return($userOpts) if(!$key);
  return($userOpts->{$key});
}

sub GetUserOptsDefault {
  my $self = shift;
  my $key = shift;
  my $userOpts = $self->GetUserOpts($key);
  return if(!defined($userOpts));
  my (undef, undef, undef, $default) = @$userOpts;
  return($default);
}

1;
