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

sub Socket {
  my $self = shift;
  $self->{'Socket'} = shift if(@_);
  return($self->{'Socket'});
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
      $self->PrintLine('[*] Got connection from ' . $self->Socket->peerhost . ':' . $self->Socket->peerport);
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
  if($self->Socket) {
    $self->Socket->shutdown(2);
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
