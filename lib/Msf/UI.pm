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
    my $dir = @_ ? shift : $self->_BaseDir . '/encoders/internal';
    return($self->LoadModules($dir, 'Msf::Encoder::'));
}
sub LoadNops {
#fixme external nops
    my $self = shift;
    my $dir = @_ ? shift : $self->_BaseDir . '/nops/internal';
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

sub LoadPayloads_old
{
    my $self = shift;
    my $dir = @_ ? shift : $self->_BaseDir . '/payloads';
    my $int = $dir . '/internal';
    my $ext = $dir . '/external';
    my $res = {};
    
    return $res if ! -d $dir;
    
    # Load internal payloads first
    if (opendir(PAY, $int))
    {
        while (defined(my $entry = readdir(PAY)))
        {
            my $path = "$int/$entry";
            next if ! -f $path;

            my $pay = Pex::Payload->new($path, "i");
            $res->{$pay->Name()} = $pay if $pay;
        }
        closedir(PAY);
    }
    
    # Now load all external payloads
    if (opendir(PAY, $ext))
    {
        while (defined(my $entry = readdir(PAY)))
        {
            my $path = "$ext/$entry";
            if (! $^O eq "MSWin32")
            {
                next if ! -x $path;
            } else {
                next if ! -f $path;
            }
            
            my $pay = Pex::Payload->new($path, "e");
            $res->{$pay->Name()} = $pay if $pay;
        }
        closedir(PAY);
    }    
    
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

    # Make sure that all the supported architectures and os's
    # of the exploit are also supported by the payload

    # If a payload whats to support all architectures or
    # all os's, they just have an empty array
    # (This is the same for exploits)

    foreach my $os (@{$exploit->OS}) {
      last if(!@{$payload->OS});
      next CHECK if(!scalar(grep { $_ eq $os } @{$payload->OS}));
    }
    foreach my $arch (@{$exploit->Arch}) {
      last if(!@{$payload->Arch});
      next CHECK if(!scalar(grep { $_ eq $arch } @{$payload->Arch}));
    }

    # So for keys, we want to make sure none of the keys in exploit
    # are in payload.
    foreach my $key (@{$exploit->Keys}) {
      next CHECK if(scalar(grep { $_ eq $key } @{$payload->Keys}));
    }
    
    next if($exploit->Priv < $payload->Priv);

#fixme Eventually we should also factor in the Encoder Size, even though we will catch it in Encode
    next if($exploit->Payload->{'Size'} < $payload->Size);

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
      $self->FatalError('Exploit supports architecture(s) that the encoder and/or nop generator do not.');
    }
  }
  return($encoder->Encode);
}

#fixme
# I think the best way to do encoding is just to
# Look at the environment and choose the encoder passed on that
sub MakeEncoder {
    my $self = shift;
    # Even though there is already a entry in default in Msf::ConfigFile
    # This is important enough to just default again anyway
    my $name = $self->GetEnv('Encoder') || 'Msf::Encoder::Pex';
    my $encoder = $name->new(@_);

    return($encoder);
}
sub MakeNop {
    my $self = shift;
    # Even though there is already a entry in default in Msf::ConfigFile
    # This is important enough to just default again anyway
    my $name = $self->GetEnv('Nop') || 'Msf::Nop::Pex';
    my $nop = $name->new(@_);
    return($nop);
}

1;
__DATA__

sub PatternCreate
{
    my ($length) = @_;
    my ($X, $Y, $Z);
    my $res;

    while (1)
    {
        for my $X ("A" .. "Z") { for my $Y ("a" .. "z") { for my $Z (0 .. 9) {
           $res .= $X;
           return $res if length($res) >= $length;

           $res .= $Y;
           return $res if length($res) >= $length;

           $res .= $Z;
           return $res if length($res) >= $length;
        }}}
    }
}

sub PatternOffset
{
       my ($pattern, $address) = @_;
       my @results;
       my ($idx, $lst) = (0,0);

       $address = pack("L", eval($address));
       $idx = index($pattern, $address, $lst);

       while ($idx > 0)
       {
            push @results, $idx;
            $lst = $idx + 1;
            $idx = index($pattern, $address, $lst);
       }
       return @results;
}

sub Unblock {
    my $fd = shift || return;
    
    # Using the "can" method $fd->can() does not work
    # when dealing with subclasses of IO::Handle :(
    if (ref($fd) =~ /Socket|GLOB/)
    {
        $fd->blocking  (0);
        $fd->autoflush (1);
    }
    
    if ($^O ne "MSWin32")
    {
        my $flags = fcntl($fd, F_GETFL,0);
        fcntl($fd, F_SETFL, $flags|O_NONBLOCK);
    }
}


# Create a UDP socket to a random internet host and use it to 
# determine our local IP address, without actually sending data
sub InternetIP {
    my $res = "127.0.0.1";
    my $s = IO::Socket::INET->new(PeerAddr => '4.3.2.1', PeerPort => 53, Proto => "udp") 
    || return $res;    
    $res = $s->sockhost;   
    $s->close();
    undef($s);
    return $res;
}


1;
