#!/usr/bin/perl

package Msf::PayloadComponent::ReverseConnection;
use strict;
use base 'Msf::PayloadComponent::ConnectionHandler';
use IO::Socket::INET;
use IO::Select;

my $info = {
  'UserOpts' =>
    {
      'LHOST'         =>  [1, 'ADDR', 'Local address to receive connection'],
      'LPORT'         =>  [1, 'PORT', 'Local port to receive connection'],
    },
};

sub new {
  my $class = shift;
  my $self = $class->SUPER::new(@_);
  $self->_Info($self->MergeHash($info, $self->_Info));
  return($self);
}

sub ListenerSock {
  my $self = shift;
  $self->{'ListenerSock'} = shift if(@_);
  return($self->{'ListenerSock'});
}
sub ListenerSelector {
  my $self = shift;
  $self->{'ListenerSelector'} = shift if(@_);
  return($self->{'ListenerSelector'});
}

sub SetupHandler {
  my $self = shift;
  my $port = $self->GetVar('LPORT');

  my $sock = IO::Socket::INET->new(
    'LocalPort' => $port,
    'Proto'     => 'tcp',
    'ReuseAddr' => 1,
    'Listen'    => 5,
    'Blocking'  => 0,
  );

  if(!$sock) {
    $self->SetError("Could not start listener: $!");
    return;
  }

  $sock->autoflush(1);
  $self->ListenerSock($sock);
  $self->ListenerSelector(IO::Select->new($sock));
  $self->PrintLine('[*] Starting Reverse Handler.');
}

sub CheckHandler {
  my $self = shift;

  my @ready = $self->ListenerSelector->can_read(.5);
  if(@ready) {
    my $sock = $ready[0]->accept();
    $self->SocketIn($sock);
    $self->SocketOut($sock);
    return(1);
  }

  return(0);
}

sub ShutdownHandler {
  my $self = shift;
  $self->SUPER::ShutdownHandler;
  if($self->ListenerSock) {
    $self->ListenerSock->shutdown(2);
  }
  $self->PrintLine('[*] Exiting Reverse Handler.');
}

1;
