package Msf::UI;
use strict;
use base 'Msf::Base';
use Msf::Config;
use Pex::Encoder;

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
    return(dirname(File::Spec::Functions::rel2abs($0)) . '\\' . $self->_ConfigFile);
  }
  return("$ENV{'HOME'}/" . $self->_ConfigFile);
}

sub LoadExploits {
    my $self = shift;
    my $dir = @_ ? shift : $self->_BaseDir . '/exploits';
    return($self->LoadModules($dir, 'Msf::Exploit::'));
}
sub LoadEncoders {
#fixme external encoders
    my $self = shift;
    my $dir = @_ ? shift : $self->_BaseDir . '/encoders';
    return($self->LoadModules($dir, 'Msf::Encoder::'));
}
sub LoadNops {
#fixme external nops
    my $self = shift;
    my $dir = @_ ? shift : $self->_BaseDir . '/nops';
    return($self->LoadModules($dir, 'Msf::Nop::'));
}
sub LoadPayloads {
#fixme external payloads
    my $self = shift;
    my $dir = @_ ? shift : $self->_BaseDir . '/payloads';
    return($self->LoadModules($dir, 'Msf::Payload::'));
}

sub LoadModules {
    my $self = shift;
    my $dir = shift;
    my $prefix = shift;
    my $res = {};

    return $res if ! -d $dir;
    return $res if ! opendir(DIR, $dir);

    while (defined(my $entry = readdir(DIR)))
    {
        my $path = "$dir/$entry";
        next if ! -f $path;
        next if ! -r $path;
        next if $entry !~ /.pm$/;

        $entry =~ s/\.pm$//g;
        $entry = $prefix . $entry;

        # remove the module from global namespace
        delete($::{$entry."::"});

        # load the module via do since we dont import
        $self->PrintDebugLine(3, "Doing $path");
#        eval("do '$path'");
        do $path;

        if ($@) { $self->PrintLine("[*] Error loading $path: $@") }
        else  { $res->{$entry} = $entry->new() }
    }
    closedir(DIR);
    return($res);
}

sub MatchPayloads {
  my $self = shift;
  my $exploit = shift;
  my $payloads = shift;

  my $match = { };

CHECK:
  foreach my $payloadName (keys(%$payloads)) {
    my $payload = $payloads->{$payloadName};

    # Match the OS arrays of both the exploits and payloads
    # If an exploit has say 2 os's (linux and bsd maybe)
    # we will match all payloads that are linux or bsd
    if(@{$exploit->OS}) {
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
    if(@{$exploit->Arch}) {
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
    if($exploit->Size < $payload->Size) {
      $self->PrintDebugLine(3, $payload->Name . " failed, payload is too large for exploit, Exploit: " . $exploit->Size . " Payload: " . $payload->Size);
      next CHECK;
    }

    $match->{$payloadName} = $payloads->{$payloadName};
  }
  return($match);
}

sub Encode {
# Nopping is done inside of the Pex::Encode class
  my $self = shift;
  my ($exploit, $payload) = @_;

  my $nop = $self->MakeNop(@_);
  my $encoder = $self->MakeEncoder(@_, $nop);

#fixme

  # In order to support Encoders that support multiple architectures
  # and nop generators that support multiple architectures, etc
  # we need to make sure that every arch in exploit is in encoder
  # and is in nops
  my $exploitArch = $exploit->Arch;
  my $encoderArch = $encoder->Arch;
  my $nopArch = $nop->Arch;

  foreach my $arch (@{$exploitArch}) {
    if(!scalar(grep {$_ eq $arch} @{$encoderArch}) || !scalar(grep {$_ eq $arch} @{$nopArch})) {
      $self->PrintDebug(1, "Arch: $arch\nExploit: " . join(' ', @{$exploitArch}) .
        "\nEncoder: " . join(' ', @{$encoderArch}) . "\nNop: " . join(' ', @{$nopArch}) . "\n");
      $self->SetError('Exploit supports architecture(s) that the encoder and/or nop generator do not.');
      return;
    }
  }
  my $encoded = $encoder->Encode;
  $self->SetError($encoder->GetError);
  return($encoded);
}

sub MakeEncoder {
    my $self = shift;
    # Even though there is already an entry in default in Msf::Config
    # This is important enough to just default again anyway
    my $name = $self->GetEnv('Encoder') || 'Msf::Encoder::Pex';
    my $encoder = $name->new(@_);

    return($encoder);
}

sub MakeNop {
    my $self = shift;
    # Even though there is already a entry in default in Msf::Config
    # This is important enough to just default again anyway
    my $name = $self->GetEnv('Nop') || 'Msf::Nop::Pex';
    my $nop = $name->new(@_);
    return($nop);
}

sub SaveConfig {
  my $self = shift;
  Msf::Config->SaveConfig($self->ConfigFile);
}

1;
