
###############

##
#         Name: Module.pm
#       Author: spoonm <ninjatools [at] hush.com>
#      Version: $Revision$
#  Description: Parent class for all modules.
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Msf::Module;
use strict;
use base 'Msf::Base';
use Socket;

my $defaults =
{
  'Name'        => 'No Name',
  'Version'     => '0.0',
  'Authors'     => [ ],
  'Arch'        => [ ],
  'OS'          => [ ],
  'Keys'        => [ ],
  'Priv'        => [ ],
  'UserOpts'    => { },
  'Refs'        => [ ],
  'Description' => 'No Description',
};

sub new {
  my $class = shift;
  my $hash = @_ ? shift : { };
  my $self = bless($hash, $class);
  $self->SetDefaults($self->MergeHashRec($self->_InfoDefaults, $defaults));
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
sub _InfoDefaults {
  my $self = shift;
  $self->{'_InfoDefaults'} = { } if(!defined($self->{'_InfoDefaults'}));
  $self->{'_InfoDefaults'} = shift if(@_);
  return($self->{'_InfoDefaults'});
}

sub SetDefaults {
  my $self = shift;
  my $hash = shift;
  $self->_Info($self->MergeHashRec($self->_Info, $hash));
}

sub Info {
  my $self = shift;
  return($self->_Info);
}


# Generic Accessors
sub Name        { my $self = shift; return($self->Info->{'Name'}); }
sub Version     { my $self = shift; return($self->Info->{'Version'}); }
sub Authors     { my $self = shift; return($self->Info->{'Authors'}); }
sub Arch        { my $self = shift; return($self->Info->{'Arch'}); }
sub OS          { my $self = shift; return($self->Info->{'OS'}); }
sub Keys        { my $self = shift; return($self->Info->{'Keys'}); }
sub Priv        { my $self = shift; return($self->Info->{'Priv'}); }
sub UserOpts    { my $self = shift; return($self->Info->{'UserOpts'}); }
sub Refs        { my $self = shift; return($self->Info->{'Refs'}); }

sub Description {
  my $self = shift;
  return($self->Info->{'Description'});
}

sub Loadable {
  return(1);
}

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
      # Option is not required, set it to the default
      if (defined($dflt)) { $self->SetVar($key, $dflt) }
    }
    elsif(uc($type) eq 'ADDR') {
      my $addr = gethostbyname($value);
      if(!$addr) {
        $self->SetError("Invalid address $value for $key");
        return;
      }
      # Replace a hostname with an IP address
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
      
      # Replace common true/false values with a simple 1/0
      if($value =~ /^(y|t|1)$/i) {
        $self->SetVar($key, 1);
      } else {
        $self->SetVar($key, 0);
      }
    }
    elsif(uc($type) eq 'PATH') {
      if(! -r $value) {
        $self->SetError("Invalid path $value for $key");
        return;
      }
    }
    elsif(uc($type) eq 'BYTE') {
      if($value > 255) {
        $self->SetError("Invalid byte $value for $key");
        return;
      }
      $self->SetVar($key,  $value+0);
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

# Convert References to a list of URL's
sub RefLinks {
  my $self = shift;
  my @urls = ();
  
  foreach my $ref (@{ $self->Refs }) {
    if (ref($ref) eq 'ARRAY') {
        push @urls, $self->RefConvert(@{ $ref });    
    }
    else {
        push @urls, $self->RefConvert('URL', $ref);
    }
  }

  return \@urls;
}

# Convert Reference Type and Data to a given URL
sub RefConvert {
  my $self = shift;
  my $type = shift;
  my $data = shift;
  
  if ($type eq 'URL') {
    return $data;
  }
  
  if ($type eq 'OSVDB') {
    return 'http://www.osvdb.org/'.$data;
  }
  
  if ($type eq 'CVE') {
    return 'http://cve.mitre.org/cgi-bin/cvename.cgi?name='.$data;
  }
  
  if ($type eq 'BID') {
    return 'http://www.securityfocus.com/bid/'.$data;
  }
  
  if ($type eq 'MSB') {
    return 'http://www.microsoft.com/technet/security/bulletin/'.$data.'.mspx';
  } 
  
  if ($type eq 'NSS') {
    return 'http://www.nessus.org/plugins/index.php?view=single&id='.$data;
  }
  
  if ($type eq 'MIL') {
    return 'http://www.milw0rm.com/metasploit/'.$data;
  } 
  
  return $data;
}

1;
