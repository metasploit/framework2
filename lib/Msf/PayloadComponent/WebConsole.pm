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

sub _HandleConsole {
  my $self = shift;
  my $out;
	
  # Get handle to browser
  my $bs = $self->GetVar('_BrowserSocket');
  
  # Create listener socket
  my $sock = IO::Socket::INET->new(
    'Proto'     => 'tcp',
    'ReuseAddr' => 1,
    'Listen'    => 5,
    'Blocking'  => 0,
  );  
  
  if (! $sock) {
      $out = "WebConsole: _HandleConsole(): Failed to bind a port for the proxy shell: $!<br\>\n";
	  $bs->Send(sprintf("%x\r\n%s\r\n", length($out), $out));
	  return;
  }
  
  # Display listener link to browser
  my $addr = Pex::Utils::SourceIP($bs->PeerAddr);

  $out = "[*] Proxy shell started on ".
	     "<a href='telnet://$addr:".$sock->sockport."'>".
	     "$addr:".$sock->sockport."</a><br\>\n";
	
  $bs->Send(sprintf("%x\r\n%s\r\n", length($out), $out));
	

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
      $out = "[*] Shutting down proxy shell due to timeout<br\>\n";
	  $bs->Send(sprintf("%x\r\n%s\r\n", length($out), $out));
	  return;
  }
  
  my $cs = Pex::Socket::Tcp->new_from_socket($csock);

  $out = "[*] Connection to proxy shell from ".$csock->peerhost.":".$csock->peerport."<br\>\n";
  $bs->Send(sprintf("%x\r\n%s\r\n", length($out), $out));
	  
  $cs->Send("\r\nMetasploit Web Interface Shell Proxy\r\n\r\n");
 
  # Map connected socket to PipeLocal(In|Out);
  $self->{'WebShell'} = $csock;  

  # Configure the Pipes
  $self->PipeLocalOut	($csock);
  $self->PipeLocalIn	($csock);
  $self->PipeLocalName	($csock->sockhost);

  # Call upwards to TextConsole's _HandleConsole
  $self->SUPER::_HandleConsole;
}

1;
