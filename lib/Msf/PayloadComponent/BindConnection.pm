#!/usr/bin/perl

package Msf::PayloadComponent::BindConnection;
use strict;
use base 'Msf::PayloadComponent::ConnectionHandler';
use IO::Socket::INET;

my $info = {
  'UserOpts' =>
    {
      'LPORT' => [1, 'PORT', 'Listening port for bind shell'],
    },
};

sub new {
  my $class = shift;
  my $self = $class->SUPER::new(@_);
  $self->_Info($self->MergeHash($info, $self->_Info));
  return($self);
}

sub SetupHandler {
  my $self = shift;
  $self->PrintLine('[*] Starting Bind Handler.');
}

sub CheckHandler {
  my $self = shift;
  my $host = $self->GetVar('RHOST');
  my $port = $self->GetVar('LPORT');

  my $sock = IO::Socket::INET->new(
    'PeerHost'  => $host,
    'PeerPort'  => $port,
    'Proto'     => 'tcp',
    'Blocking'  => 0,
  );

  return(0) if(!$sock);
  $sock->autoflush(1);
  my $loop = 4;
  while($sock && $loop--) {
    if($sock->connected) {
      $self->SocketIn($sock);
      $self->SocketOut($sock);
      return(1);
    }
    select(undef, undef, undef, .2);
  }

  return(0);
}

sub ShutdownHandler {
  my $self = shift;
  $self->PrintLine('[*] Exiting Bind Handler.');
}

1;
