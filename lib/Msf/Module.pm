package Msf::Module;
use strict;
use base 'Msf::Base';
use Socket;

sub new {
  my $class = shift;
  my $hash = @_ ? shift : { };
  my $self = bless($hash, $class);

  # Make sure Info and Defaults always exists
  # Makes life easier checking elsewhere
  if(!defined($self->{'Info'})) {
    $self->PrintDebugLine(4, "$self: No Info hash, setting to { }");
    $self->{'Info'} = { };
  }
  if(!defined($self->{'Defaults'})) {
    $self->PrintDebugLine(4, "$self: No Defaults hash, setting to { }");
    $self->{'Defaults'} = { };
  }
  return($self);
}

# Internal accessors/mutators
sub _Info {
  my $self = shift;
  $self->{'Info'} = shift if(@_);
  return($self->{'Info'});
}

sub SetDefaults {
  my $self = shift;
  my $hash = shift;
  $self->MergeHash($self->_Info, $hash);
}


#fixme Screw this mess
# Generic
sub Name        { my $self = shift; return defined($self->{'Info'}->{'Name'}) ? $self->{'Info'}->{'Name'} : undef }
sub Version     { my $self = shift; return defined($self->{'Info'}->{'Version'}) ? $self->{'Info'}->{'Version'} : undef }
sub Author      { my $self = shift; return defined($self->{'Info'}->{'Author'}) ? $self->{'Info'}->{'Author'} : undef }
sub Arch        { my $self = shift; return defined($self->{'Info'}->{'Arch'}) ? $self->{'Info'}->{'Arch'} : undef }
sub OS          { my $self = shift; return defined($self->{'Info'}->{'OS'}) ? $self->{'Info'}->{'OS'} : undef }
sub Keys        { my $self = shift; return defined($self->{'Info'}->{'Keys'}) ? $self->{'Info'}->{'Keys'} : undef }
sub Priv        { my $self = shift; return defined($self->{'Info'}->{'Priv'}) ? $self->{'Info'}->{'Priv'} : undef }
sub UserOpts    { my $self = shift; return defined($self->{'Info'}->{'UserOpts'}) ? $self->{'Info'}->{'UserOpts'} : undef }
sub Refs        { my $self = shift; return defined($self->{'Info'}->{'Refs'}) ? $self->{'Info'}->{'Refs'} : undef }
sub Description { my $self = shift; return defined($self->{'Info'}->{'Description'}) ? $self->{'Info'}->{'Description'} : undef }

# Used?
sub AutoOpts    { my $self = shift; return defined($self->{'Info'}->{'AutoOpts'}) ? $self->{'Info'}->{'AutoOpts'} : undef }

# Exploit Specific (move to Msf::Exploit?)
sub Payload     { my $self = shift; return defined($self->{'Info'}->{'Payload'}) ? $self->{'Info'}->{'Payload'} : undef }

# Payload Specific (move to Msf::Payload?)
sub Type     { my $self = shift; return defined($self->{'Info'}->{'Type'}) ? $self->{'Info'}->{'Type'} : undef }
sub Size     { my $self = shift; return defined($self->{'Info'}->{'Size'}) ? $self->{'Info'}->{'Size'} : undef }


sub Validate {
  my $self = shift;
  my $userOpts = $self->{'Info'}->{'UserOpts'};

  return(1) if(!defined($userOpts));

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
# 4) KEY in Defaults
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
  $val = $self->GetDefaultValue($key);
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
  return($self->SetDefault($key, $val)) if(defined($self->GetDefault($key)));
  # Even thought it was is in UserOpts, we just mask it in Defaults
  return($self->SetDefault($key, $val)) if(defined($self->GetOptsDefault($key)));
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
  $val = $self->GetDefaultValue($key);
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
  return($self->SetDefault($key, $val)) if(defined($self->GetDefault($key)));
  # Even thought it was is in UserOpts, we just mask it in Defaults
  return($self->SetDefault($key, $val)) if(defined($self->GetOptsDefault($key)));
  return;
}

sub Advanced {
  my $self = shift;
  return($self->{'Defaults'});
}


# The Default/Advanced hash
sub GetDefault {
  my $self = shift;
  my $key = shift;
  return if(!defined($self->{'Defaults'}));
  return if(!defined($self->{'Defaults'}->{$key}));
  return($self->{'Defaults'}->{$key});
}

sub GetDefaultValue {
  my $self = shift;
  my $key = shift;

  # Incase we get called with our scope prepended.
  my $removeChunk = $self->SelfName . '::';
  my $find = index($key, $removeChunk);
  substr($key, $find, length($removeChunk), '') if($find != -1);
  return if(!defined($self->{'Defaults'}));
  return if(!defined($self->{'Defaults'}->{$key}));
  return($self->{'Defaults'}->{$key}->[0]);
}

sub SetDefault {
  my $self = shift;
  my $key = shift;
  my $val = shift;
  return if(!defined($self->{'Defaults'}));
  return($self->{'Defaults'}->{$key} = $val);
}

# UserOpts hash
sub GetUserOpts {
  my $self = shift;
  my $key = shift;
  my $userOpts = $self->{'Info'}->{'UserOpts'};
  $userOpts = { } if(!$userOpts);
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
