package Msf::UI;
use strict;
use base 'Msf::Base';
use Msf::Config;
use Pex::Encoder;
use Pex::Utils;

sub new {
  my $class = shift;
  my $self = $class->SUPER::new({
    'BaseDir'  => shift,
    'ConfigFile' => @_ ? shift : '.msfconfig',
  });
  $self->_Initalize;
  return($self);
}

sub _BaseDir {
  my $self = shift;
  $self->{'BaseDir'} = shift if(@_);
  return($self->{'BaseDir'});
}
sub _ConfigFile {
  my $self = shift;
  $self->{'ConfigFile'} = shift if(@_);
  return($self->{'ConfigFile'});
}

sub _Initalize {
  my $self = shift;
  Msf::Config->PopulateConfig($self->ConfigFile);
}

sub ConfigFile {
  my $self = shift;
  if($^O eq 'WIN32') {
    return($self->ScriptBase . '\\' . $self->_ConfigFile);
  }
  return("$ENV{'HOME'}/" . $self->_ConfigFile);
}

sub LoadExploits {
  my $self = shift;
  my $dir = @_ ? shift : $self->_BaseDir . '/exploits';
  return($self->LoadModules($dir, 'Msf::Exploit::'));
}
sub LoadEncoders {
  my $self = shift;
  my $dir = @_ ? shift : $self->_BaseDir . '/encoders';
  return($self->LoadModules($dir, 'Msf::Encoder::'));
}
sub LoadNops {
  my $self = shift;
  my $dir = @_ ? shift : $self->_BaseDir . '/nops';
  return($self->LoadModules($dir, 'Msf::Nop::'));
}
sub LoadPayloads {
  my $self = shift;
  my $dir = @_ ? shift : $self->_BaseDir . '/payloads';
  return($self->LoadModules($dir, 'Msf::Payload::'));
}

sub LoadModules {
  my $self = shift;
  my $dir = shift;
  my $prefix = shift;
  my $modules = { };

  return $modules if(!-d $dir);
  return $modules if(!opendir(DIR, $dir));

  while (defined(my $entry = readdir(DIR))) {
    my $path = "$dir/$entry";
    next if(!-f $path);
    next if(!-r $path);
    next if($entry !~ /.pm$/);

    $entry =~ s/\.pm$//g;
    $entry = $prefix . $entry;

    # remove the module from global namespace
    delete($::{$entry."::"});

    # load the module via do since we dont import
    $self->PrintDebugLine(3, "Doing $path");
    do $path;

    if($@) {
      $self->PrintLine("[*] Error loading $path: $@");
      delete($::{$entry."::"});
      next;
    }

    my $module = $entry->new();

    if(!$module->Loadable) {
      $self->PrintLine("[*] Loadable failed for $entry");
      $module->PrintError;
      delete($::{$entry."::"});
      next;
    }

    $modules->{$entry} = $module;
  }
  closedir(DIR);
  return($modules);
}

sub MatchPayloads {
  my $self = shift;
  my $exploit = shift;
  my $payloads = shift;

  my $match = { };

CHECK:
  foreach my $payloadName (keys(%$payloads)) {
    my $payload = $payloads->{$payloadName};

    # If a exploit's arch or os is empty, it means they support allows
    # Same with a payload

    # Match the OS arrays of both the exploits and payloads
    # If an exploit has say 2 os's (linux and bsd maybe)
    # we will match all payloads that are linux or bsd
    if(@{$exploit->OS} && @{$payload->OS}) {
      my $valid = 0;
      foreach my $os (@{$payload->OS}) {
        $valid = 1 if(scalar(grep { $_ eq $os } @{$exploit->OS}));
      }
      if(!$valid) {
        # OS is not in payload
        $self->PrintDebugLine(3, $payload->Name . " failed, didn't match OS");
        next CHECK;
      }
    }
    
    # Match the Arch arrays of both the exploits and payloads
    if(@{$exploit->Arch} && @{$payload->Arch}) {
      my $valid = 0;
      foreach my $arch (@{$payload->Arch}) {
        $valid = 1 if(scalar(grep { $_ eq $arch } @{$exploit->Arch}));
      }
      if(!$valid) {
        # Arch is not in payload
        $self->PrintDebugLine(3, $payload->Name . " failed, didn't match Arch");
        next CHECK;
      }
    }

    # If the exploit has a any keys set, we need to make sure that the
    # matched payload also has the same keys. This allows us to create
    # specific payloads for weird exploit scenarios (for instance, where
    # the process doesn't have a valid heap (hdm)
    foreach my $key (@{$exploit->Keys}) {
      if(!scalar(grep { $_ eq $key } @{$payload->Keys})) {
        $self->PrintDebugLine(3, $payload->Name . " failed, keys do not match");
        next CHECK;
      }
    }
    
    if($exploit->Priv < $payload->Priv) {
      $self->PrintDebugLine(3, $payload->Name . " failed, payload needs more priviledge than exploit provides");
      next CHECK;
    }

    #fixme Eventually we should also factor in the Encoder Size, even though we will catch it in Encode
    if($exploit->PayloadSpace < $payload->Size) {
      $self->PrintDebugLine(3, $payload->Name . " failed, payload is too large for exploit, Exploit: " . $exploit->PayloadSpace . " Payload: " . $payload->Size);
      next CHECK;
    }

    $match->{$payloadName} = $payloads->{$payloadName};
  }
  return($match);
}

sub Encode {
  my $self = shift;
  my $exploit = $self->GetTempEnv('_Exploit');
  my $payload = $self->GetTempEnv('_Payload');

  my @nops = $self->GetNops;
  my @encoders = $self->GetEncoders;

  my $payloadArch = $payload->Arch;
  my $payloadOS = $payload->OS;

  my $badChars = $exploit->PayloadBadChars;
  my $prependEncoder = $exploit->PayloadPrependEncoder;
  my $exploitSpace = $exploit->PayloadSpace;
  my $encodedPayload;

  if($self->BadCharCheck($badChars, $prependEncoder)) {
    # This should never happen unless the exploit coder is dumb, but might as well check
    $self->SetError('Bad Characters in prependEncoder');
    return;
  }

  foreach my $encoderName (@encoders) {
    $self->PrintDebugLine(1, "Tring $encoderName");
    my $encoder = $self->MakeEncoder($encoderName);
    if(!$encoder) {
      $self->PrintDebugLine(1, "Failed to make encoder $encoderName");
      next;
    }
    my $encoderArch = $encoder->Arch;
    my $encoderOS = $encoder->OS;

    if(!$self->ListCheck($payloadArch, $encoderArch)) {
      $self->PrintDebugLine(2, "$encoderName failed, doesn't support all architectures");
      $self->PrintDebugLine(4, "payloadArch: " . join(',', @{$payloadArch}));
      $self->PrintDebugLine(4, "encoderArch: " . join(',', @{$encoderArch}));
      next;
    }
    if(!$self->ListCheck($payloadOS, $encoderOS)) {
      $self->PrintDebugLine(2, "$encoderName failed, doesn't support all operating systems");
      $self->PrintDebugLine(4, "payloadOS: " . join(',', @{$payloadOS}));
      $self->PrintDebugLine(4, "encoderOS: " . join(',', @{$encoderOS}));
      next;
    }

    my $rawShell = $exploit->PayloadPrepend . $payload->Build . $exploit->PayloadAppend;
    my $encodedShell = $encoder->Encode($rawShell, $badChars);

    if(!$encodedShell) {
      $self->PrintDebugLine(1, "$encoderName failed to return an encoded payload");
      next;
    }

    if($encoder->IsError) {
      $self->PrintDebugLine(1, "$encoderName failed with an error");
      $self->PrintDebugLine(4, $encoder->GetError);
      $encoder->ClearError;
      next;
    }

    if($self->BadCharCheck($badChars, $encodedShell)) {
      $self->PrintDebugLine(2, "$encoderName failed, bad chars in encoded payload");
      $self->PrintDebugLine(5, "encoded payload:");
      $self->PrintDebugLine(5, Pex::Utils::BufferC($encodedShell));
      next;
    }

    $encodedShell = $prependEncoder . $encodedShell;
    
    if(length($encodedShell) > $exploitSpace - $exploit->PayloadMinNops) {
      $self->PrintDebugLine(2, "$encoderName failed, encoded payload too large for exploit");
      $self->PrintDebugLine(4, "ExploitSpace: $exploitSpace");
      $self->PrintDebugLine(4, "EncodedLength: " . length($encodedShell)); 
      $self->PrintDebugLine(4, 'MinNops: ' . $exploit->PayloadMinNops . ' MaxNops: ' . $exploit->PayloadMaxNops);
      next;
    }

    $encodedPayload = Msf::EncodedPayload->new($rawShell, $encodedShell);
    last;
  }

  if(!$encodedPayload) {
    $self->SetError("No encoders succeeded");
    return;
  }

  my $maxNops = defined($exploit->PayloadMaxNops) ? $exploit->PayloadMaxNops : 10000000;
  my $emptySpace = $exploitSpace - length($encodedPayload->EncodedPayload);
  my $nopSize = $maxNops < $emptySpace ? $maxNops : $emptySpace;
  my $success = 0;

  foreach my $nopName (@nops) {
    $self->PrintDebugLine(1, "Tring $nopName");
    my $nop = $self->MakeNop($nopName);
    if(!$nop) {
      $self->PrintDebugLine(1, "Failed to make nop generator $nop");
      next;
    }
    my $nopArch = $nop->Arch;
    my $nopOS = $nop->OS;

    if(!$self->ListCheck($payloadArch, $nopArch)) {
      $self->PrintDebugLine(2, "$nopName failed, doesn't support all architectures");
      $self->PrintDebugLine(4, "payloadArch: " . join(',', @{$payloadArch}));
      $self->PrintDebugLine(4, "nopArch: " . join(',', @{$nopArch}));
      next;
    }
    if(!$self->ListCheck($payloadOS, $nopOS)) {
      $self->PrintDebugLine(2, "$nopName failed, doesn't support all operating systems");
      $self->PrintDebugLine(4, "payloadOS: " . join(',', @{$payloadOS}));
      $self->PrintDebugLine(4, "nopOS: " . join(',', @{$nopOS}));
      next;
    }

    my $nops = $nop->Nops($nopSize, $badChars);

    if($nop->IsError) {
      $self->PrintDebugLine(1, "$nopName failed with an error");
      $self->PrintDebugLine(4, $nop->GetError);
      $nop->ClearError;
      next;
    }

    if(length($nops) != $nopSize) {
      $self->PrintDebugLine(2, "$nopName failed, error generating nops");
      next;
    }

    if($self->BadCharCheck($badChars, $nops)) {
      $self->PrintDebugLine(2, "$nopName failed, bad chars in nops");
      next;
    }

    $success = 1;
    $encodedPayload->SetNops($nops);
    last;
  }

  if(!$success) {
    $self->SetError("No nop generators succeeded");
    return;
  }
#  $self->SetTempEnv('EncodedPayload', $encodedPayload);
  return($encodedPayload);
}

sub GetEncoders {
  my $self = shift;
  my @preferred = split(',', $self->GetEnv('Encoder'));
  my @encoders;
  foreach my $encoder (keys(%{$self->GetTempEnv('_Encoders')})) {
    next if(scalar(grep { $_ eq $encoder } @preferred));
    push(@encoders, $encoder);
  }
  return(@preferred, @encoders);
}
sub GetNops {
  my $self = shift;
  my @preferred = split(',', $self->GetEnv('Nop'));
  my @nops;
  foreach my $nop (keys(%{$self->GetTempEnv('_Nops')})) {
    next if(scalar(grep { $_ eq $nop } @preferred));
    push(@nops, $nop);
  }
  return(@preferred, @nops);
}
sub MakeEncoder {
  my $self = shift;
  my $name = shift;
  # Check to see if the encoder is in our encoders list
  return if(!scalar(grep { $_ eq $name } keys(%{$self->GetTempEnv('_Encoders')})));

  my $encoder = $name->new;
  return($encoder);
}
sub MakeNop {
  my $self = shift;
  my $name = shift;
  # Check to see if the encoder is in our nops list
  return if(!scalar(grep { $_ eq $name } keys(%{$self->GetTempEnv('_Nops')})));

  my $nop = $name->new;
  return($nop);
}

# Example usage: ListCheck($exploitArch, $encoderArch)
# All of list1 must be in list2 unless list2 is empty
sub ListCheck {
  my $self = shift;
  my $list1 = shift || [ ];
  my $list2 = shift || [ ];
  if(@{$list2}) { # A empty list means it supports all
    foreach my $entry (@{$list1}) {
      if(!scalar(grep { $_ eq $entry } @{$list2})) {
        return(0);
      }
    }
  }
  return(1);
}
sub BadCharCheck {
  my $self = shift;
  my $badChars = shift;
  my $string = shift;
  foreach (split('', $badChars)) {
    if(index($string, $_) != -1) {
      return(1);
    }
  }
  return(0);
}

sub SaveConfig {
  my $self = shift;
  Msf::Config->SaveConfig($self->ConfigFile);
}

1;
