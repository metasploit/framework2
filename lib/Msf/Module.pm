package Msf::Module;
use strict;
use base 'Msf::Base';


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
sub Name        { my $obj = shift; return defined($obj->{'Info'}->{'Name'}) ? $obj->{'Info'}->{'Name'} : undef }
sub Version     { my $obj = shift; return defined($obj->{'Info'}->{'Version'}) ? $obj->{'Info'}->{'Version'} : undef }
sub Author      { my $obj = shift; return defined($obj->{'Info'}->{'Author'}) ? $obj->{'Info'}->{'Author'} : undef }
sub Arch        { my $obj = shift; return defined($obj->{'Info'}->{'Arch'}) ? $obj->{'Info'}->{'Arch'} : undef }
sub OS          { my $obj = shift; return defined($obj->{'Info'}->{'OS'}) ? $obj->{'Info'}->{'OS'} : undef }
sub Keys        { my $obj = shift; return defined($obj->{'Info'}->{'Keys'}) ? $obj->{'Info'}->{'Keys'} : undef }
sub Priv        { my $obj = shift; return defined($obj->{'Info'}->{'Priv'}) ? $obj->{'Info'}->{'Priv'} : undef }
sub UserOpts    { my $obj = shift; return defined($obj->{'Info'}->{'UserOpts'}) ? $obj->{'Info'}->{'UserOpts'} : undef }
sub Refs        { my $obj = shift; return defined($obj->{'Info'}->{'Refs'}) ? $obj->{'Info'}->{'Refs'} : undef }
sub Description { my $obj = shift; return defined($obj->{'Info'}->{'Description'}) ? $obj->{'Info'}->{'Description'} : undef }

# Used?
sub AutoOpts    { my $obj = shift; return defined($obj->{'Info'}->{'AutoOpts'}) ? $obj->{'Info'}->{'AutoOpts'} : undef }

# Exploit Specific (move to Msf::Exploit?)
sub Payload     { my $obj = shift; return defined($obj->{'Info'}->{'Payload'}) ? $obj->{'Info'}->{'Payload'} : undef }

# Payload Specific (move to Msf::Payload?)
sub Type     { my $obj = shift; return defined($obj->{'Info'}->{'Type'}) ? $obj->{'Info'}->{'Type'} : undef }
sub Size     { my $obj = shift; return defined($obj->{'Info'}->{'Size'}) ? $obj->{'Info'}->{'Size'} : undef }






sub Validate {
  my $self = shift;
  my $userOpts = $self->{'Info'}->{'UserOpts'};

  return(1) if(!defined($userOpts));

  foreach my $key (keys(%{$userOpts})) {
    my ($type, $desc) = @{$userOpts->{$key}};
    my $value = $self->GetVar($key);

    if(!defined($value)) {
      $self->FatalError("Missing required option: $key");
    }
    elsif(uc($type) eq 'ADDR') {
      my $addr = gethostbyname($value);
      if(!$addr) {
        $self->FatalError("Invalid address $value for $key");
      }
#fixme Should we pass them the ip?
#      $self->SetVar($addr);
    }
    elsif(uc($type) eq 'PORT') {
      if($value < 1 || $value > 65535) {
        $self->FatalError("Invalid port $value for $key");
      }
    }
    elsif(uc($type) eq 'BOOL') {
      if($value !~ /^(y|n|t|f|0|1)$/i) {
        $self->FatalError("Invalid boolean $value for $key");
      }
    }
    elsif(uc($type) eq 'PATH') {
      if(! -r $value) {
        $self->FatalError("Invalid path $value for $key");
      }
    }
  }
  return(1);
}

# Pecking order:
# 1) KEY in Config
# 2) SelfName::KEY in Config
# 3) KEY in Defaults
# 4) KEY in UserOpts
sub GetVar {
  my $self = shift;
  my $key = shift;
  my $val;

  $val = $self->GetTempEnv($key);
  return($val) if(defined($val));
  $val = $self->GetEnv($key);
  return($val) if(defined($val));
  $val = $self->GetEnv($self->SelfName . '::' . $key);
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
  return($self->SetEnv($key, $val)) if(defined($self->GetEnv($key)));
  return($self->SetEnv($self->SelfName . '::' . $key, $val)) if(defined($self->GetEnv($self->SelfName . '::' . $key)));
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

  $val = $self->GetEnv($self->SelfName . '::' . $key);
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

  return($self->SetEnv($self->SelfName . '::' . $key, $val)) if(defined($self->GetEnv($self->SelfName . '::' . $key)));
  return($self->SetDefault($key, $val)) if(defined($self->GetDefault($key)));
  # Even thought it was is in UserOpts, we just mask it in Defaults
  return($self->SetDefault($key, $val)) if(defined($self->GetOptsDefault($key)));
  return;
}

sub Advanced {
  my $self = shift;
  my $default = { };

  my $selfName = $self->SelfName . '::';
  foreach my $key (keys(%{$self->{'Defaults'}})) {
    $default->{$selfName . $key} = $self->{'Defaults'}->{$key};
  }
  return($default);
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
