package Msf::PayloadComponent::TextConsole;
use strict;
use base 'Msf::Payload';
use IO::Handle;
use IO::Select;

sub LogDir {
  my $self = shift;
  $self->{'LogDir'} = shift if(@_);
  return($self->{'LogDir'});
}

sub LogFile {
  my $self = shift;
  $self->{'LogFile'} = shift if(@_);
  return($self->{'LogFile'});
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
  
  $sockIn->blocking(1);
  $sockIn->autoflush(1);
  $sockOut->blocking(1);
  $sockOut->autoflush(1);
  
  $consoleIn->blocking(1);
  $consoleIn->autoflush(1);
  $consoleOut->blocking(1);
  $consoleOut->autoflush(1);

  my $selector = IO::Select->new($consoleIn, $sockIn);

  $self->StartLog;

LOOPER:
  while($loop) {
    my @ready = $selector->can_read;
    foreach my $ready (@ready) {
      if($ready == $consoleIn) {
        my $data = $consoleIn->getline;
        $self->SendLog($data);
        $data = $self->SendFilter($data);
        $sockOut->send($data);
      }
      elsif($ready == $sockIn) {
        my $data;
        $sockIn->recv($data, 4096);
        last LOOPER if(!length($data));
        $data = $self->RecvFilter($data);
        $self->RecvLog($data);
        print $consoleOut $data;
      }
      else {
        print "Well thats a bug.\n";
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
  if($self->GetVar('Logging') ne 'Enabled') {
    $self->LogDir('');
    return;
  }

  my $logDir = $self->GetVar('LogDir');
  $logDir = $self->CreateLogDir($logDir);
  $self->LogDir($logDir);
  if(!defined($logDir)) {
    $self->PrintLine('[*] Error creating log directory.');
    return;
  }

  my $logFile = time() . '_' . $self->GetVar('_Exploit')->SelfEndName . '_' . $self->SocketIn->peerhost . '.log';
  $self->LogFile($logFile);

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
  $headers .= "\n";
  if(!$self->WriteLog($headers)) {
    $self->PrintLine('[*] Disabling logging.');
    $self->LogDir('');
    $self->LogFile('');
    return;
  }
}

sub StopLog {
}

sub SendLog {
  my $self = shift;
  my $data = shift;
  return if(!defined($self->LogFile));
  $self->WriteLog(time() . ' CLIENT ' . unpack('H*', $data) . "\n");
}
sub RecvLog {
  my $self = shift;
  my $data = shift;
  return if(!defined($self->LogFile));
  $self->WriteLog(time() . ' SERVER ' . unpack('H*', $data) . "\n");
}

sub WriteLog {
  my $self = shift;
  my $data = shift;
  my $logDir = $self->LogDir;
  my $logFile = $self->LogFile;
  if(!open(OUTFILE, ">>$logDir/$logFile")) {
    $self->PrintLine('[*] Error writing to log file: $logDir/$logFile: $!');
    return(0);
  }
  print OUTFILE $data;
  close(OUTFILE);
  return(1);
}

sub CreateLogDir {
  my $self = shift;
  my $dir = defined($ENV{'HOME'}) ? $ENV{'HOME'} : $self->ScriptBase;
  $dir .= '/.msflogs';

  return if(! -d $dir && !mkdir($dir, 0700));
  return($dir);
}

1;
