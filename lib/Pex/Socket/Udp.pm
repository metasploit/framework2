#!/usr/bin/perl
###############

##
#      Version: $Revision$
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Pex::Socket::Udp;
use strict;
use base 'Pex::Socket::Socket';

sub new {
  my $class = shift;
  my $self = bless({ }, $class);

  my $hash = { @_ };
  $self->SetOptions($hash);

  return if(!$self->_MakeSocket);
  return($self)
}

sub SetOptions {
  my $self = shift;
  my $hash = shift;

  $self->Broadcast($hash->{'Broadcast'}) if(exists($hash->{'Broadcast'}));
  $self->SUPER::SetOptions($hash);
}

sub Broadcast {
  my $self = shift;
  $self->{'Broadcast'} = shift if(@_);
  return($self->{'Broadcast'});
}

sub _MakeSocket {
  my $self = shift;

  return if($self->GetError);

  my %config = (
    'PeerAddr'   => $self->Hostname,
    'PeerPort'   => $self->Port,
    'Proto'      => 'udp',
    'ReuseAddr'  => 1,
  );

  $config{'LocalPort'} = $self->LocalPort if($self->LocalPort);
  $config{'Broadcast'} = 1 if($self->Broadcast || $config{'PeerAddr'} =~ /\.255$/);

  my $sock = IO::Socket::INET->new(%config);

  if(!$sock) {
    $self->SetError('Socket failed: ' . $!);
    return;
  }

  $sock->blocking(0);
  $sock->autoflush(1);

  $self->Socket($sock);
  return($sock->fileno);
}

1;
