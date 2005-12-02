
###############

##
#         Name: TextUI.pm
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

package Msf::TextUI;
use strict;
use base 'Msf::UI';
use Msf::ColPrint;
use IO::Socket;
use POSIX;
use Msf::Logging;
use Msf::Logo;

sub new {
  my $class = shift;
  my $self = $class->SUPER::new(@_);

  # configure STDERR/STDERR for text display
  select(STDERR); $|++;
  select(STDOUT); $|++;
  return($self);
}

# ugly and ghetto, w00t
sub WordWrap {
  # We stole this from somewhere
  my $self = shift;
  my $text = shift;
  my $indent = @_ ? shift : 4;
  my $size = @_ ? shift : 60;
  $indent = " " x $indent;
  my $fullText;
  foreach my $text (split("\n\n", $text)) {
    $text =~ s/(?:^|\G\n?)(?:(.{1,$size})(?:\s|\n|$)|(\S{$size})|\n)/$1$2\n/sg;
    $text =~ s/^/$indent/gm;
    $fullText .= $text . "\n";
  }
  substr($fullText, -1, 1, '');
  return($fullText);
}

sub DumpExploits {
  my $self     = shift;
  my $indent   = shift;
  my $exploits = shift;
  my $class    = shift;
  
  my $count = 0;
  my $col = Msf::ColPrint->new($indent, 2);
  
  foreach my $mod_file (sort keys %{$exploits}) {
    my $mod_class = $exploits->{$mod_file}->ModuleClass;
    my $mod_name  = $exploits->{$mod_file}->Name;
	
	# Only display modules belonging to this class
    if ($class) {
      next if $class ne $mod_class;
      $col->AddRow($mod_file, $mod_name);
    }
    # Otherwise display all exploits and a column with the class identifier
    else {
      $col->AddRow($mod_file, $mod_name);	  
    }
  }
  
  return($col->GetOutput);
}

sub DumpPayloads {
  my $self = shift;
  my $indent = shift;
  my $payloads = shift;
  my $col = Msf::ColPrint->new(2, 4);
  foreach my $key (sort(keys(%{$payloads}))) {
    # no neccesary right now, but just to support the oo stuff in the future
    $payloads->{$key}->_Load;

    $col->AddRow($key,
      $payloads->{$key}->Name);
  }
  return($col->GetOutput);
}

sub DumpEncoders {
  my $self = shift;
  my $indent = shift;
  my $encoders = shift;
  my $col = Msf::ColPrint->new(2, 4);
  foreach my $key (sort(keys(%{$encoders}))) {
    $col->AddRow($key,
      $encoders->{$key}->Name);
  }
  return($col->GetOutput);
}

sub DumpNops {
  my $self = shift;
  my $indent = shift;
  my $nops = shift;
  my $col = Msf::ColPrint->new(2, 4);
  foreach my $key (sort(keys(%{$nops}))) {
    $col->AddRow($key,
      $nops->{$key}->Name);
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
      $output .= "\n" . $self->WordWrap($options->{$opt}->[1], 4, 60);

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
  $output .=   '     Class: ' . $exploit->ModuleClass . "\n";
  $output .=   '   Version: ' . $exploit->Version . "\n";
  $output .=   ' Target OS: ' . join(", ", @{$exploit->OS}) . "\n";
  $output .=   '  Keywords: ' . join(", ", @{$exploit->Keys}) ."\n"; 
  $output .=   'Privileged: ' . ($exploit->Priv ? "Yes" : "No") . "\n";

  if ($exploit->DisclosureDate) {
    $output .=   'Disclosure: ' . $exploit->DisclosureDate . "\n";
  }
  
  $output .=   "\n";
  
  $output .=   "Provided By:\n";
  foreach (@{$exploit->Authors}) {
    $output .= "    $_\n";
  }
  $output .= "\n";
  
  $output .=   "Available Targets:\n";
  foreach ($exploit->TargetsList) { $output .= "    " . $_ . "\n" }
  
  $output .= "\n";
  $output .= "Available Options:\n\n";

  $output .= $self->DumpOptions(4, 'Exploit', $exploit);

  if ($exploit->Payload) {
    $output .= "Payload Information:\n";
    $output .= "    Space: " . $exploit->PayloadSpace . "\n";
    $output .= "    Avoid: " . length($exploit->PayloadBadChars) . " characters\n";
    $output .= "   " . ($exploit->PayloadKeysType eq 'or' ? '|' : '&');
    $output .= " Keys: " . join(' ', @{$exploit->PayloadKeysParsed}) . "\n\n";
    $output .= "Nop Information:\n";
    $output .= " SaveRegs: " . join(' ', @{$exploit->NopSaveRegs}) . "\n";
    $output .= "   " . ($exploit->NopKeysType eq 'or' ? '|' : '&');
    $output .= " Keys: " . join(' ', @{$exploit->NopKeysParsed}) . "\n\n";
    $output .= "Encoder Information:\n";
    $output .= "   " . ($exploit->EncoderKeysType eq 'or' ? '|' : '&');
    $output .= " Keys: " . join(' ', @{$exploit->EncoderKeysParsed}) . "\n\n";
  }

  my $desc = $self->WordWrap($exploit->Description, 4, 66);
  $output .= "Description:\n$desc\n";
  
  $output .= "References:\n";
  foreach (@{$exploit->RefLinks}) { $output .= "    " . $_ . "\n" }
  $output .= "\n";
  return($output);
}

sub DumpPayloadSummary {
  my $self = shift;
  my $p = shift;
  # dynamic oo stuff, make sure inheritence is setup right
  $p->_Load;
  my $output;

  $output .= "       Name: " . $p->Name . "\n";
  $output .= "    Version: ".  $p->Version . "\n";
  $output .= "     OS/CPU: " . join(", ", @{$p->OS}) . "/" . join(", ", @{$p->Arch}) . "\n"; 
  $output .= "Needs Admin: " . ($p->Priv ? "Yes" : "No") . "\n";
  $output .= " Multistage: " . ($p->Multistage ? "Yes" : "No") . "\n";
  $output .= " Total Size: " . $p->Size . "\n";
  $output .= "       Keys: " . join(' ', @{$p->Keys}) . "\n";
  $output .= "\n";

  $output .= "Provided By:\n";
  foreach (@{$p->Authors}) {
    $output .= "    $_\n";
  }
  $output .= "\n";
  
  $output .= "Available Options:\n";
  $output .= $self->DumpOptions(4, 'Options', $p);
  $output .= "Advanced Options:\n";
  $output .= $self->DumpAdvancedOptions(4, 'Advanced', $p);

  my $desc = $self->WordWrap($p->Description, 4, 60);
  $output .= "Description:\n$desc\n";
  return($output);
}
sub DumpEncoderSummary {
  my $self = shift;
  my $e = shift;
  my $output;

  $output .= "       Name: " . $e->Name . "\n";
  $output .= "    Version: ".  $e->Version . "\n";
  $output .= "     OS/CPU: " . join(", ", @{$e->OS}) . "/" . join(", ", @{$e->Arch}) . "\n";
  $output .= "       Keys: " . join(' ', @{$e->Keys}) . "\n";
  $output .= "\n";

  $output .= "Provided By:\n";
  foreach (@{$e->Authors}) {
    $output .= "    $_\n";
  }
  $output .= "\n";

  $output .= "Advanced Options:\n";
  $output .= $self->DumpAdvancedOptions(4, 'Advanced', $e);

  my $desc = $self->WordWrap($e->Description, 4, 60);
  $output .= "Description:\n$desc\n";
  return($output);
}
sub DumpNopSummary {
  my $self = shift;     
  my $e = shift;   
  my $output;
    
  $output .= "       Name: " . $e->Name . "\n";
  $output .= "    Version: ".  $e->Version . "\n";
  $output .= "     OS/CPU: " . join(", ", @{$e->OS}) . "/" . join(", ", @{$e->Arch}) . "\n";
  $output .= "       Keys: " . join(' ', @{$e->Keys}) . "\n";
  $output .= "\n";
    
  $output .= "Provided By:\n";
  foreach (@{$e->Authors}) {
    $output .= "    $_\n";
  }                       
  $output .= "\n";
    
  $output .= "Advanced Options:\n";
  $output .= $self->DumpAdvancedOptions(4, 'Advanced', $e);
    
  my $desc = $self->WordWrap($e->Description, 4, 60);
  $output .= "Description:\n$desc\n";                
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
  my @targets = $exploit->TargetsList;

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
  
  if ($exploit->Payload && $payloadName) {
    print $self->DumpOptions(2, 'Payload', $payload);
  }
  
  if(@targets) {
    my $name = 'Target Not Specified';
    my $target = $exploit->GetVar('TARGET');
    $target = $exploit->DefaultTarget if(!defined($target));
    if($target < @targets && $target >= 0) {
      $name = $targets[$target];
    }
    $self->PrintLine('  Target: ' . $name);
  }
  else {
    $self->PrintLine('  Target: Targetless Exploit');
  }
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
    $self->PrintLine(sprintf("  %2d  $targets[$i]", $i));
  }
  $self->PrintLine;
}


sub Check {
  my $self = shift;
  my $exploit = $self->GetTempEnv('_Exploit');

  $exploit->Validate; # verify that all required exploit options have been set
  return if($exploit->PrintError);

  Msf::Logging->PrintLine('[' . localtime(time()) . '] ' . $exploit->SelfEndName . ' CHECK FROM ' . $exploit->GetVar('LHOST') . ":" . $exploit->GetVar('LPORT') . ' TO ' . $exploit->GetVar('RHOST') . ":" . $exploit->GetVar('RPORT') );

  my $res = $exploit->Check;
# This isn't ready yet.
#  Msf::Logging->PrintLine('[' . localtime(time()) . '] ' . $exploit->SelfEndName . ' CHECK RESULT ' . $exploit->CheckCode($res));
  return if($exploit->PrintError);

  # The check routine prints out data and returns 1/0
  return $res;
}


sub Exploit {
  my $self = shift;
  my $exploit = $self->GetTempEnv('_Exploit');

  my $payload = $self->GetTempEnv('_Payload');
  $payload->_Load if($payload);

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

  Msf::Logging->PrintLine('[' . localtime(time()) . '] ' . $exploit->SelfEndName . ' EXPLOIT FROM ' . $exploit->GetVar('LHOST') . ":" . $exploit->GetVar('LPORT') . ' TO ' . $exploit->GetVar('RHOST') . ":" . $exploit->GetVar('RPORT') . ' USING PAYLOAD ' . $exploit->GetVar('PAYLOAD') . ' AND TARGET ' . $targets[$target] );

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
		$payload->ExtraDelay();
      exit(0);
    }
  }

  # print "\n";

  return;
}

sub PrintAsciiLogo {
    print STDOUT "\n".Msf::Logo::Random()."\n";
}

1;
