package Msf::PayloadComponent::TextConsole;
use strict;
use base 'Msf::Payload';
use IO::Handle;
use IO::Select;
use Msf::Logging;

sub Log {
  my $self = shift;
  $self->{'Log'} = shift if(@_);
  return($self->{'Log'});
}
sub ConsoleIn {
    my $self = shift;
    return IO::Handle->new_from_fd(0, '<');
}

sub ConsoleOut {
    my $self = shift;
    return IO::Handle->new_from_fd(1, '>');
}

sub HandleConsole {
  my $self = shift;
  my $sockIn = $self->SocketIn;
  my $sockOut = $self->SocketOut;
  my $loop = 1;

  print "\n";

  my $sigHandler = sub {
    print "Caught ctrl-c, exit connection? [y/n] ";
    my $answer = <STDIN>;
    chomp($answer);
    if(lc($answer) eq 'y') {
      $loop = 0;
    }
  };

  my ($osigTerm, $osigInt) = ($SIG{'TERM'}, $SIG{'INT'});
  $SIG{'TERM'} = $sigHandler;
  $SIG{'INT'} = $sigHandler;

  my $consoleIn  = $self->ConsoleIn;
  my $consoleOut = $self->ConsoleOut;
  
  foreach ($sockIn, $sockOut, $consoleIn, $consoleOut) {
    $_->blocking(1);
    $_->autoflush(1);
  }

  my $selector = IO::Select->new($consoleIn, $sockIn);

  $self->StartLog;

LOOPER:
  while($loop) {
    my @ready = $selector->can_read;
    foreach my $ready (@ready) {
      if($ready == $consoleIn) {
        my $data = $consoleIn->getline;
        last LOOPER if (! length($data));
        $self->SendLog($data);
        $data = $self->SendFilter($data);
        
        last LOOPER if(!$sockOut || !$sockOut->connected);
        
        $sockOut->send($data);
      }
      elsif($ready == $sockIn) {
        my $data;
        $sockIn->recv($data, 4096);
        last LOOPER if(!length($data));
        $data = $self->RecvFilter($data);
        $self->RecvLog($data);
        
        last LOOPER if(!$consoleOut || !$consoleOut->opened);
        
        print $consoleOut $data;
      }
    }
  }

  $self->StopLog;

  ($SIG{'TERM'}, $SIG{'INT'}) = ($osigTerm, $osigInt);
}

sub SendFilter {
  my $self = shift;
  my $data = shift;
  return($data);
}

sub RecvFilter {
  my $self = shift;
  my $data = shift;
  return($data);
}

sub StartLog {
  my $self = shift;
  if(!$self->GetVar('Logging')) {
    $self->Log('');
    return;
  }

  my $logFile = time() . '_' . $self->GetVar('_Exploit')->SelfEndName . '_' . $self->SocketIn->peerhost . '.log';

  Msf::Logging->PrintLine('[' . localtime(time()) . '] ' . $self->GetVar('_Exploit')->SelfEndName . ' EXPLOIT SUCCESS');

  $self->Log(Msf::Logging->new($logFile));
  if(!$self->Log) {
    $self->PrintLine('[*] Error in logging, disabling.');
    $self->Log('');
    return;
  }

  my $headers = 'Time: ' . localtime(time()) . ' (' . time() . ")\n";
  $headers .= 'Name: ' . $self->GetVar('_Exploit')->Name . ' (' . $self->GetVar('_Exploit')->SelfName . ')' . "\n";
  $headers .= 'Options:';
  my $env = $self->GetEnv;
  foreach (keys(%{$env})) {
    my $key = $_;
    my $val = $env->{$key};
    next if(substr($key, 0, 1) eq '_' || ref($val));
    $val =~ s/"/\"/g;
    $headers .= qq{ $key="$val"};
  }
  $headers .= "\n";
  $headers .= 'SocketIn: ' . $self->SocketIn->sockhost . ':' . $self->SocketIn->sockport . ' ' . $self->SocketIn->peerhost . ':' . $self->SocketIn->peerport . "\n";
  $headers .= 'SocketOut: ' . $self->SocketOut->sockhost . ':' . $self->SocketOut->sockport . ' ' . $self->SocketOut->peerhost . ':' . $self->SocketOut->peerport . "\n";
  
  if ($self->ConsoleIn->can('sockhost')) {
     $headers .= 'ConsoleIn: ' . $self->ConsoleIn->sockhost . ':' . $self->ConsoleIn->sockport . ' ' . $self->ConsoleIn->peerhost . ':' . $self->ConsoleIn->peerport . "\n";
  }
  if ($self->ConsoleOut->can('sockhost')) {
     $headers .= 'ConsoleOut: ' . $self->ConsoleOut->sockhost . ':' . $self->ConsoleOut->sockport . ' ' . $self->ConsoleOut->peerhost . ':' . $self->ConsoleOut->peerport . "\n";
  }  
  
  $headers .= "\n";
  $self->Log->Print($headers);
  if($self->Log->IsError) {
    $self->PrintLine('[*] Disabling logging: ' . $self->Log->GetError);
    $self->Log('');
    return;
  }
  Msf::Logging->PrintLine('[' . localtime(time()) . '] ' . $self->GetVar('_Exploit')->SelfEndName . ' SESSION LOG ' . $logFile);
}

sub StopLog {
}

sub SendLog {
  my $self = shift;
  my $data = shift;
  return if(!$self->Log);
  $self->Log->PrintLine(time() . ' CLIENT ' . unpack('H*', $data));
}
sub RecvLog {
  my $self = shift;
  my $data = shift;
  return if(!$self->Log);
  $self->Log->PrintLine(time() . ' SERVER ' . unpack('H*', $data));
}

1;
