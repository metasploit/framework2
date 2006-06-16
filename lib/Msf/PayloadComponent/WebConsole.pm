
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
use FindBin qw{$RealBin};

sub LoadConsole {
  my $self = shift;
  my $out;

  # Get handle to browser
  my $bs = $self->GetVar('_BrowserSocket');
  
  # Get handles to stdio
  my $pipeIn  = $self->GetVar('_PipeInput');
  my $pipeOut = $self->GetVar('_PipeOutput');
  
  # Get handle to parent web server
  my $gIPC = $self->GetVar('_GhettoIPC');
  
  # Get our session IO
  my $sid = $self->GetVar('_SessionID');

  $out = "[*] Shell started on ".
         "<a href='/SESSIONS?MODE=LOAD&SID=$sid' target='_blank'>".
		 "session $sid</a><br>\n";
  $bs->Send(sprintf("%x\r\n%s\r\n", length($out), $out));
  
	
  # Configure the Pipes
  $self->PipeLocalOut	($pipeIn);
  $self->PipeLocalIn	($pipeOut);
  $self->PipeLocalName	($bs->PeerAddr);

  # Shut down web browser socket
  $out = "\n</blockquote></blockquote>".
	       "</div><br/></body></html>\n";
  $bs->Send(sprintf("%x\r\n%s\r\n", length($out), $out));
  $bs->Close;

  # Kick off the shell server  
  $gIPC->printflush("NEW $sid $$\n");
  
  return;
}

1;
