package Msf::TextUI;
use strict;
use base 'Msf::UI';
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

sub WordWrap {
  my $self = shift;
  my $text = shift;
  my $indent = @_ ? shift : 4;
  my $size = @_ ? shift : 60;
  my $indent = " " x $indent;
  $text =~ s/(?:^|\G\n?)(?:(.{1,$size})(?:\s|\n|$)|(\S{$size})|\n)/$1$2\n/sg;
  $text =~ s/\n/\n$indent/g;
  return($text);
}

sub DumpExploits {
  my $self = shift;
  my $indent = shift;
  my $exploits = shift;
  my $count = 0;
  my $col = Msf::ColPrint->new($indent, 2);
  foreach my $key (sort(keys(%{$exploits}))) {
    $col->AddRow($key, $exploits->{$key}->Name);
  }
  return($col->GetOutput);
}

sub DumpPayloads {
  my $self = shift;
  my $indent = shift;
  my $payloads = shift;
  my $col = Msf::ColPrint->new(2, 4);
  foreach my $key (sort(keys(%{$payloads}))) {
    $col->AddRow($key,
        $payloads->{$key}->Description);
  }
  return($col->GetOutput);
}

sub DumpOptions {
  my $self = shift;
  my $indent = shift;
  my $col = Msf::ColPrint->new($indent, 4);
  while(@_) {
    my $type = shift;
    my $object = shift;
    my $options = $object->UserOpts || { };
    $col->AddRow($type . ':', 'Name', 'Default', 'Description');
    $col->AddRow('__hr__', '__hr__', '__hr__', '__hr__');
    foreach my $opt (keys(%{$options}))
    {
        $col->AddRow($options->{$opt}->[0] ? "required" : "optional",
            $opt, $object->GetVar($opt), $options->{$opt}->[2]);
    }
    $col->AddRow;
  }
  return($col->GetOutput);
}

sub DumpAdvancedOptions {
  my $self = shift;
  my $indent = shift;
  $indent = " " x $indent;
  my $output;
  while(@_) {
    my $type = shift;
    my $object = shift;
    my $options = $object->Advanced || { };
    $type .= ' (' . $object->SelfName . ')';
    $output .= "${indent}$type:\n${indent}" . ('-' x (length($type) + 1)) . "\n";
    my $i = 0;
    foreach my $opt (keys(%{$options})) {
      if($i++) {
        $output .= "\n\n";
      }
      $output .= "${indent}Name:     $opt\n${indent}Default:  " . $object->GetLocal($opt) . "\n";
      $output .= "\n${indent}" . $self->WordWrap($options->{$opt}->[1], 2, 60);

    }
    $output .= "\n" if(@_);
  }
  $output .= "\n";
  return($output);
}

sub DumpExploitSummary {
  my $self = shift;
  my $exploit = shift;
  my $output;
  $output .=   '      Name: ' . $exploit->Name . "\n";
  $output .=   '   Version: ' . $exploit->Version . "\n";
  $output .=   ' Target OS: ' . join(", ", @{$exploit->OS}) . "\n";
  $output .=   'Privileged: ' . ($exploit->Priv ? "Yes" : "No") . "\n";
  $output .=   "\n";
  
  $output .=   "Provided By:\n";
  $output .=   "    " . $exploit->Author . "\n\n";
  
  $output .=   "Available Targets:\n";
  foreach ($exploit->Targets) { $output .= "    " . $_ . "\n" }
  
  $output .= "\n";
  $output .= "Available Options:\n";

  print $self->DumpOptions(4, 'Exploit', $exploit);

  if ($exploit->Payload) {
    $output .= "\n";
    $output .= "Payload Information:\n";
    $output .= "    Space: " . $exploit->PayloadSpace . "\n";
    $output .= "    Avoid: " . scalar(split(//, $exploit->PayloadBadChars)) . " characters\n";
  }

  my $desc = $self->WordWrap($exploit->Description, 4, 60);
  $output .= "\n";
  $output .= "Description:\n    $desc\n";
  
  $output .= "References:\n";
  foreach (@{$exploit->Refs}) { $output .= "    " . $_ . "\n" }

  return($output);
}

sub DumpPayloadSummary {
  my $self = shift;
  my $p = shift;
  my $output;
  
    $output .= "       Name: " . $p->Name . "\n";
    $output .= "    Version: ".  $p->Version . "\n";
    $output .= "     OS/CPU: " . join(", ", @{$p->OS}) . "/" . join(", ", @{$p->Arch}) . "\n"; 
    $output .= "Needs Admin: " . ($p->Priv ? "Yes" : "No") . "\n";
    $output .= " Total Size: " . $p->Size . "\n";
    $output .= "\n";
    
    $output .= "Provided By:\n";
    $output .= "    " . $p->Author . "\n\n";
    
    $output .= "Available Options:\n";
    my %mopts = %{$p->UserOpts};
    foreach my $k (sort(keys(%mopts)))
    {
        my $reqd = $mopts{$k}->[0] ? "required" : "optional";
        $output .= "    $reqd:" .  (" " x 13) . $k . (" " x (15 - length($k))) . $mopts{$k}->[2] . "\n";
    }
    
    my $desc = $self->WordWrap($p->Description, 4, 60);
    $desc =~ s/\n/\n    /g;
    $output .= "\n";
    $output .= "Description:\n    $desc\n";
    return($output);
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

  if($exploit->Payload && !defined($payloadName)) {
    $self->PrintLine('[*] You must specify a payload before viewing the available options.');
    return;
  }

  if($exploit->Payload && !$payload) {
    $self->PrintLine("[*] Invalid payload specified: $payloadName");
    return;
  }

  $self->PrintLine;
  $self->PrintLine('Exploit and Payload Options');
  $self->PrintLine('===========================');
  $self->PrintLine;
  print $self->DumpOptions(2, 'Exploit', $exploit);
  print $self->DumpOptions(2, 'Payload', $payload) if($exploit->Payload);
  $self->PrintLine;
  $self->PrintLine;
}

sub AdvancedOptions {
  my $self = shift;
  my $exploit = $self->GetTempEnv('_Exploit');
  my $payload = $self->GetTempEnv('_Payload');
  my $payloadName = $self->GetTempEnv('_PayloadName');

  if($exploit->Payload && !defined($payloadName)) {
    $self->PrintLine('[*] You must specify a payload before viewing the available options.');
    return;
  }

  if($exploit->Payload && !$payload) {
    $self->PrintLine("[*] Invalid payload specified: $payloadName");
    return;
  }

  $self->PrintLine;
  $self->PrintLine('Exploit and Payload Advanced Options');
  $self->PrintLine('====================================');
  $self->PrintLine;
  print $self->DumpAdvancedOptions(2, 'Payload', $payload) if($exploit->Payload);
  print $self->DumpAdvancedOptions(2, 'Exploit', $exploit);
  $self->PrintLine;
  $self->PrintLine;
}

sub Targets {
  my $self = shift;
  my $exploit = $self->GetTempEnv('_Exploit');

  my @targets = $exploit->Targets;
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
  print "Check:   $res\n";
}


sub Exploit {
  my $self = shift;
  my $exploit = $self->GetTempEnv('_Exploit');
  my $payload = $self->GetTempEnv('_Payload');
  my $payloadName = $self->GetTempEnv('_PayloadName');

  if($exploit->Payload && !defined($payloadName)) {
    $self->PrintLine('[*] You must specify a payload before viewing the available options.');
    return;
  }

  if($exploit->Payload && !$payload) {
    $self->PrintLine("[*] Invalid payload specified: $payloadName");
    return;
  }
 
  $exploit->Validate;
  return if($exploit->PrintError);

  # validate payload module options
  if($payload) {
    $payload->Validate;
    return if($payload->PrintError);
  }

  my @targets = $exploit->Targets;
  my $target = $self->GetEnv('TARGET');

  if(defined($target) && !defined($targets[$target])) {
    $self->PrintLine('[*] Invalid target specified.');
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
