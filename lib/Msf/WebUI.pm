#!/usr/bin/perl
###############

##
#         Name: WebUI.pm
#       Author: spoonm <ninjatools [at] hush.com>
#      Version: $Revision$
#  Description: Instantiable class derived from UI with methods useful to
#               text-based user interfaces.
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Msf::WebUI;
use strict;
use base 'Msf::TextUI';
use Msf::ColPrint;
use IO::Socket;
use POSIX;

sub new {
  my $class = shift;
  my $self = $class->SUPER::new(@_);

  # configure STDERR/STDERR for text display
  select(STDERR); $|++;
  select(STDOUT); $|++;
  
  # create a new empty printline buffer
  $self->SetTempEnv('PrintLine', [ ]);
  $self->_OverridePrintLine(\&PrintLine);
  
  return($self);
}

# We overload the UI::PrintLine call so that we can
# buffer exploit output and display as needed
sub PrintLine {
    my $self = shift;
    my $msg = shift;
    
    # If we are exploit mode, write output to browser
    if (my $s = $self->GetEnv('BROWSER'))
    {
        $s->send("$msf <br>\n");
        return;
    }
    
    my @buffer = @{$self->GetEnv('PrintLine')};
    push @buffer, $msg;
    $self->SetTempEnv('PrintLine', \@buffer);
}

sub DumpLines {
    my $self = shift;
    my @res  = @{$self->GetEnv('PrintLine')};
    $self->SetTempEnv('PrintLine', [ ])
    return \@res;
}


sub Check {
  my $self = shift;
  my $exploit = $self->GetTempEnv('_Exploit');

  $exploit->Validate; # verify that all required exploit options have been set
  return if($exploit->PrintError);

  my $res = $exploit->Check;
  return if($exploit->PrintError);

  # The check routine prints out data and returns 1/0
  return $res;
}


sub Exploit {
  my $self = shift;
  my $exploit = $self->GetTempEnv('_Exploit');
  my $payload = $self->GetTempEnv('_Payload');
  my $payloadName = $self->GetTempEnv('_PayloadName');

  if($exploit->Payload && !defined($payloadName)) {
    $self->PrintLine('[*] This exploit requires a valid payload to be specified first.');
    return;
  }

  if($exploit->Payload && !$payload) {
    $self->PrintLine("[*] Invalid payload specified: $payloadName");
    return;
  }

  $exploit->Prepare;
  return if($exploit->PrintError);
 
  $exploit->Validate;
  return if($exploit->PrintError);

  # validate payload module options
  if($payload) {
    $payload->Validate;
    return if($payload->PrintError);
  }

  my @targets = $exploit->TargetsList;
  my $target = $self->GetEnv('TARGET');

  if(defined($target) && !defined($targets[$target])) {
    $self->PrintLine('[*] Invalid target specified.');
    return;
  }
  
  # Important: Default the target to 0, maybe this should somehow
  # be in Msf::Exploit, maybe be part of the Validate process?
  $self->SetTempEnv('TARGET', 0) if(!defined($target));

  if(defined($payload)) {
    my $encodedPayload = $self->Encode;
    return if($self->PrintError || !$encodedPayload);
    $self->SetTempEnv('EncodedPayload', $encodedPayload);
  }

  my $handler = Msf::HandlerWeb->new();
  
  my ($pHandler, $cHandler);
  if($payload && $handler->can($payload->Type)) {
    $pHandler = $payload->Type;
    $cHandler = $pHandler . "_exp";
    # create the link between the child and parent processes
    if($handler->can($pHandler) && $handler->can($cHandler)) {
      my ($cSock, $pSock);
      $self->SetTempEnv('HANDLER', $handler);
      $self->SetTempEnv('HCFUNC',  $cHandler);
      $self->PrintDebugLine(3, 'Creating link between child and parent process.');

      if(!socketpair($cSock, $pSock, AF_UNIX, SOCK_STREAM, PF_UNSPEC)) {
        $self->PrintLine("[*] socketpair error: $!");
        return;
      }     
      $self->SetTempEnv('HCSOCK', $cSock);
      $self->SetTempEnv('HPSOCK', $pSock);
    }
  }

  my $child = fork();

  # Parent
  if($child) {
    if($exploit->Payload) {
      if($pHandler) {
        $self->PrintDebugLine(1, "[*] Starting handler $pHandler");
        my $res = $handler->$pHandler($child);
        kill('TERM', $child);

        if(!$res) {
          $self->PrintLine('Handler error: ' . $handler->Error);
          kill('TERM', $child);
        }
      }
      else {
        $self->PrintDebugLine(1, '[*] No handler for payload type: ' . $payload->Type);
      }
    }
    while(waitpid($child, WNOHANG) == 0) {
      sleep(1);
    }
  }
  # Child
  else {
    select(undef, undef, undef, 0.5);
    $exploit->Exploit; 
    exit(0);
  }
  print "\n";

  # End of the ride
  return;
}


1;
