#!/usr/bin/perl
##
#         Name: WebConsole.pm
#       Author: H D Moore <hdm [at] metasploit.com>
#       Author: spoonm <ninjatools [at] hush.com>
#      Version: $Revision$
#  Description: Overloaded TextConsole that provides a proxied shell
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

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

sub _HandleConsole {
  my $self = shift;

  # Get handle to browser
  my $brow = $self->GetVar('_BrowserSocket');
  my $bs = Pex::Socket::Tcp->new_from_socket($brow);
  
  # Create listener socket
  my $sock = IO::Socket::INET->new(
    'Proto'     => 'tcp',
    'ReuseAddr' => 1,
    'Listen'    => 5,
    'Blocking'  => 0,
  );  
  
  if (! $sock) {
	  $bs->Send("WebConsole: _HandleConsole(): Failed to bind a port for the proxy shell: $!\n");
	  return;
  }
  
  # Display listener link to browser
  my $addr = Pex::Utils::SourceIP($brow->peerhost);
  
  $bs->Send(
	"[*] Proxy shell started on ".
	"<a href='telnet://$addr:".$sock->sockport."'>".
	"$addr:".$sock->sockport."</a>\n"
  );

  # Accept connection from user
  my $sel = IO::Select->new($sock);
  my $clock = time();
  my $mwait = 300;
  my $csock;
  
  while (! $csock && time < ($clock+$mwait))
  {
    foreach ($sel->can_read(0.25)) { $csock = $sock->accept() }
  }
  
  if (! $csock) {
	  $bs->Send("[*] Shutting down proxy shell due to timeout\n");
	  return;
  }
  
  my $cs = Pex::Socket::Tcp->new_from_socket($csock);

  $bs->Send("[*] Connection to proxy shell from ".$csock->peerhost.":".$csock->peerport."\n");
  $cs->Send("\r\nMetasploit Web Interface Shell Proxy\r\n\r\n");
  
  
  # Map connected socket to ConsoleIn, ConsoleOut
  $self->{'WebShell'} = $csock;  
  $bs->Send("</body></html>\n");
  $bs->Close;

  # Call upwards to TextConsole's _HandleConsole
  $self->SUPER::_HandleConsole;
}

1;
