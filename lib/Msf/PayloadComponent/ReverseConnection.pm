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

sub NinjaSock {
  my $self = shift;
  $self->{'NinjaSock'} = shift if(@_);
  return($self->{'NinjaSock'});
}
sub NinjaSelector {
  my $self = shift;
  $self->{'NinjaSelector'} = shift if(@_);
  return($self->{'NinjaSelector'});
}
sub NinjaWanted {
  my $self = shift;
  return($self->GetVar('NinjaHost') && $self->GetVar('NinjaPort'));
}


sub SetupHandler {
  my $self = shift;
  return($self->NinjaSetupHandler) if($self->NinjaWanted);

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
  return($self->NinjaCheckHandler) if($self->NinjaWanted);

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
  return($self->NinjaShutdownHandler) if($self->NinjaWanted);
  $self->SUPER::ShutdownHandler;
  if($self->ListenerSock) {
    $self->ListenerSock->shutdown(2);
  }
  $self->PrintLine('[*] Exiting Reverse Handler.');
}

sub NinjaSetupHandler {
  my $self = shift;
  my $host = $self->GetVar('NinjaHost');
  my $port = $self->GetVar('NinjaPort');

  my $sock = IO::Socket::INET->new(
    'PeerHost'  => $host,
    'PeerPort'  => $port,
    'Proto'     => 'tcp',
    'Blocking'  => 0,
  );

  if(!$sock) {
    $self->SetError("Could not start sN connection: $!");
    return;
  }

  my $loop = 4;
  while($loop--) {
    last if($sock->connected);
    select(undef, undef, undef, .2);
  }
  
  if(!$sock->connected) {
    $self->SetError("Could not connect to sN control channel.");
    return;
  }

  $sock->autoflush(1);
  $self->NinjaSock($sock);
  $self->NinjaSelector(IO::Select->new($sock));
  $self->PrintLine('[*] Starting SocketNinja Handler.');
}

sub NinjaCheckHandler {
  my $self = shift;

  my @ready = $self->NinjaSelector->can_read(.5);
  if(@ready) {
    my $data;
    $self->NinjaSock->recv($data, 4096);
    return if(!length($data));

    if($data =~ /Added server/) {
      $self->PrintLine('[*] Socket Ninja has new connection.');
      return(1);
    }
  }

  return(0);
}

sub HandleConsole {
  my $self = shift;
  return if($self->NinjaWanted);
  $self->SUPER::HandleConsole;
}

sub NinjaShutdownHandler {
  my $self = shift;
  $self->SUPER::ShutdownHandler;
  if($self->NinjaSock) {
    $self->NinjaSock->shutdown(2);
  }
  $self->PrintLine('[*] Exiting SocketNinja Handler.');
}

1;
