#!/usr/bin/perl

package Msf::PayloadComponent::ConnectionHandler;
use strict;
use base 'Msf::PayloadComponent::Console';
use POSIX;

#sub new {
#  my $class = shift;
#  my $hash = @_ ? shift : { };
#  $hash = $self->MergeHash($hash, {
#    'ChildPid' => '',
#    'StopHandling' => 0,
#   });
#  my $self = $class->SUPER::new($hash);
#  return($self);
#}

sub SocketIn {
  my $self = shift;
  $self->{'SocketIn'} = shift if(@_);
  return($self->{'SocketIn'});
}
sub SocketOut {
  my $self = shift;
  $self->{'SocketOut'} = shift if(@_);
  return($self->{'SocketOut'});
}

sub ChildPid {
  my $self = shift;
  $self->{'ChildPid'} = shift if(@_);
  return($self->{'ChildPid'});
}

sub StopHandling {
  my $self = shift;
  $self->{'StopHandling'} = shift if(@_);
  return($self->{'StopHandling'});
}

sub ParentHandler {
  my $self = shift;
  my $sigHandler = sub {
    $self->StopHandling(1);
  };
  my ($osigTerm, $osigInt) = ($SIG{'TERM'}, $SIG{'INT'});
  $SIG{'TERM'} = $sigHandler;
  $SIG{'INT'} = $sigHandler;

#  $self->PrintLine('[*] Starting ' . $self->SelfName . ' Handler...');

  while(!$self->StopHandling) {
    if($self->CheckHandler) {
      if($self->SocketIn == $self->SocketOut) {
        $self->PrintLine('[*] Got connection from ' . $self->SocketIn->peerhost . ':' . $self->SocketIn->peerport);
      }
      else {
        $self->PrintLine('[*] Got connection IN: ' . $self->SocketIn->peerhost . ':' . $self->SocketIn->peerport . ' OUT: ' . $self->SocketOut->peerhost . ':' . $self->SocketOut->peerport);
      }
      $self->KillChild;
      $self->HandleConnection;
      $self->HandleConsole;
      last;
    }
    last if(waitpid($self->ChildPid, WNOHANG) != 0);
    sleep(1);
  }

  $self->ShutdownHandler;

  ($SIG{'TERM'}, $SIG{'INT'}) = ($osigTerm, $osigInt);

#  $self->PrintLine('[*] Exiting ' . $self->SelfName . ' Handler...');
}

sub SetupHandler {
  my $self = shift;
#  $self->PrintLine('Hit default SetupHandler.');
}

sub ShutdownHandler {
  my $self = shift;
  if($self->SocketIn) {
    $self->SocketIn->shutdown(2);
    $self->SocketIn->close;
  }
  if($self->SocketOut) {
    $self->SocketOut->shutdown(2);
    $self->SocketOut->close;
  }
}

sub CheckHandler {
  my $self = shift;
#  $self->PrintLine('Hit default CheckHandler.');
  return(0);
}

sub KillChild {
  my $self = shift;
  kill('KILL', $self->{'ChildPid'});
  $self->PrintDebugLine(3, 'Killing child: ' . $self->{'ChildPid'});
}

sub ChildHandler {
  my $self = shift;
  my $sock = shift;
  sleep(1);
  return;
}

sub HandleConnection {
  my $self = shift;
}

1;
