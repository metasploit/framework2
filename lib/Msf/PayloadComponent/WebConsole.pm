#!/usr/bin/perl

package Msf::PayloadComponent::WebConsole;
use strict;
use IO::Handle;
use IO::Select;
use base 'Msf::PayloadComponent::TextConsole';

sub ConsoleIn {
    my $self = shift;
    return $self->{'WebShell'} if exists($self->{'WebShell'});
    return $self->SUPER::ConsoleIn;
}

sub ConsoleOut {
    my $self = shift;
    return $self->{'WebShell'} if exists($self->{'WebShell'});
    return $self->SUPER::ConsoleOut;
}

sub HandleConsole {
  my $self = shift;

  # Get handle to browser
  my $brow = $self->GetVar('BROWSER');

  # Create listener socket
  my $sock = IO::Socket::INET->new(
    'Proto'     => 'tcp',
    'ReuseAddr' => 1,
    'Listen'    => 5,
    'Blocking'  => 0,
  );  
  
  if (! $sock) {
    $brow->send("WebConsole: HandleConsole(): Failed to bind a port for the proxy shell: $!\n");
    return;
  }
  
  # Display listener link to browser
  my $addr = Pex::InternetIP($brow->peerhost);
  
  $brow->send(
    "[*] Proxy shell started on ".
    "<a href='telnet://$addr:".$sock->sockport."'>".
    "$addr:".$sock->sockport."</a><br>\n"
  );

  # Accept connection from user
  my $sel = IO::Select->new($sock);
  my $clock = time();



  # Map connected socket to ConsoleIn, ConsoleOut
  # Call upwards to TextConsole's HandleConsole


  $self->SUPER::HandleConsole;
}

1;
