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
  return($self);
}




# ===
sub Summary {
  my $self = shift;
  my $exploit = $self->GetTempEnv('_Exploit');
  print $self->DumpExploitSummary($exploit) . "\n";
}

sub Payloads {
  my $self = shift;
  my $exploit = $self->GetTempEnv('_Exploit');
  my $payloads = $self->GetTempEnv('_Payloads');

  if (!$exploit->Payload) {
    $self->PrintLine('[*] This exploit does not use payloads.');
    return;
  }

  my $match = $self->MatchPayloads($exploit, $payloads);

  $self->PrintLine;
  $self->PrintLine('Metasploit Framework Usable Payloads');
  $self->PrintLine('====================================');
  $self->PrintLine;
  print $self->DumpPayloads(2, $match) . "\n";
}

sub Options {
  my $self = shift;
  my $exploit = $self->GetTempEnv('_Exploit');
  my $payload = $self->GetTempEnv('_Payload');
  my $payloadName = $self->GetTempEnv('_PayloadName');

  if($exploit->Payload && defined($payloadName) && !$payload) {
    $self->PrintLine("[*] Invalid payload specified: $payloadName");
    return;
  }
  
  $self->PrintLine; 
  if ($payloadName)
  {
    $self->PrintLine('Exploit and Payload Options');
    $self->PrintLine('===========================');
  } else {
    $self->PrintLine('Exploit Options');
    $self->PrintLine('===============');
  }
  
  
  $self->PrintLine;
  print $self->DumpOptions(2, 'Exploit', $exploit);
  print $self->DumpOptions(2, 'Payload', $payload) if($payloadName);
  $self->PrintLine;
  $self->PrintLine;
}

sub AdvancedOptions {
  my $self = shift;
  my $exploit = $self->GetTempEnv('_Exploit');
  my $payload = $self->GetTempEnv('_Payload');
  my $payloadName = $self->GetTempEnv('_PayloadName');

  if($exploit->Payload && defined($payloadName) && !$payload) {
    $self->PrintLine("[*] Invalid payload specified: $payloadName");
    return;
  }
  
  $self->PrintLine; 
  if ($payloadName)
  {
    $self->PrintLine('Exploit and Payload Options');
    $self->PrintLine('===========================');
  } else {
    $self->PrintLine('Exploit Options');
    $self->PrintLine('===============');
  }
  
  
  $self->PrintLine;
  print $self->DumpAdvancedOptions(2, 'Exploit', $exploit);
  print $self->DumpAdvancedOptions(2, 'Payload', $payload) if($payloadName);
  $self->PrintLine;
  $self->PrintLine;
}

sub Targets {
  my $self = shift;
  my $exploit = $self->GetTempEnv('_Exploit');

  my @targets = $exploit->TargetsList;
  if(!@targets) {
    $self->PrintLine('[*] This exploit does not define any targets.');
    return;
  }

  $self->PrintLine;
  $self->PrintLine('Supported Exploit Targets');
  $self->PrintLine('=========================');
  $self->PrintLine;
  for(my $i = 0; $i < scalar(@targets); $i++)
  {
    $self->PrintLine(sprintf("  %d  $targets[$i]", $i));
  }
  $self->PrintLine;
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

  my $handler = Msf::HandlerCLI->new();
  
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
