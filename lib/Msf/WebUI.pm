#!/usr/bin/perl
###############

##
#         Name: WebUI.pm
#       Author: spoonm <ninjatools [at] hush.com>
#       Author: H D Moore <hdm [at] metasploit.com>
#      Version: $Revision$
#  Description: Instantiable class derived from TextUI with methods useful to
#               web-based user interfaces.
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
        $s->send("$msg\n");
        return;
    }
    
    my @buffer = @{$self->GetEnv('PrintLine')};
    push @buffer, $msg;
    $self->SetTempEnv('PrintLine', \@buffer);
}

sub DumpLines {
    my $self = shift;
    my @res  = @{$self->GetEnv('PrintLine')};
    $self->SetTempEnv('PrintLine', [ ]);
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
  $exploit = $self->ModuleName($exploit)->new;

  my $payload = $self->GetTempEnv('_Payload');
  $payload = $self->ModuleName($payload)->new if($payload);

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
  
  # Default target is gauranteed by radio form (screw POST hax0rs)
  $target = $exploit->DefaultTarget if(!defined($target) && $exploit->TargetsList);

  if($target == -1) {
    $self->PrintLine('[*] Exploit does not default targets, one must be specified.');
    return;
  }
  else {
    $self->SetTempEnv('TARGET', $target);
  }

  if(defined($payload)) {
    my $encodedPayload = $self->Encode;
    return if($self->PrintError || !$encodedPayload);
    $self->SetTempEnv('EncodedPayload', $encodedPayload);
  }
  
  # WebConsole uses GetVar('BROWSER') to get socket to client
  $self->SetTempEnv('Console', 'Msf::PayloadComponent::WebConsole');

#fixme
  if(!defined($payload)) {
    $exploit->Exploit;
  }
  else {
    $payload->SetupHandler;
    return if($payload->PrintError);

    my $child = fork();
    if($child) {
      $payload->ChildPid($child);
      $payload->ParentHandler;
    }
    else {
      srand();
      $exploit->Exploit;
      sleep(1);
      exit(0);
    }
  }

  print "\n";

  return;
}

1;
