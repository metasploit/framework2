

package Msf::PayloadComponent::ConnectionHandler;
use strict;
use base 'Msf::PayloadComponent::Console';
use POSIX;

#sub new {
#  my $class = shift;
#  my $hash = @_ ? shift : { };
#  $hash = $self->MergeHashRec($hash, {
#    'ChildPid' => '',
#    'StopHandling' => 0,
#   });
#  my $self = $class->SUPER::new($hash);
#  return($self);
#}

sub ChildPid {
  my $self = shift;
  $self->{'ChildPid'} = shift if(@_);
  return($self->{'ChildPid'});
}

sub StopHandling {
  my $self = shift;
  $self->{'StopHandling'} = shift if(@_);
  return($self->{'StopHandling'});
}


sub ParentHandler {
  my $self = shift;

  # clear the StopHandling bit
  $self->StopHandling(0);

  # already killed child
  my $killedChild = 0;

  # Setup sighandle to set StopHandling bit
  my $sigHandler = sub {
    $self->SigHandler;
  };

  my ($osigTerm, $osigInt) = ($SIG{'TERM'}, $SIG{'INT'});
  $SIG{'TERM'} = $sigHandler;
  $SIG{'INT'} = $sigHandler;

#  $self->PrintLine('[*] Starting ' . $self->SelfName . ' Handler...');

  while(!$self->StopHandling) {
    if($self->CheckHandler) {
      if($self->PipeRemoteIn) { 
          $self->PrintLine('[*] Got connection from ' . $self->PipeRemoteSrc);
      }
      $self->KillChild;
      $killedChild = 1;
      $self->LoadConsole;
      $self->HandleConnection;
      $self->HandleConsole;
      last;
    }

    # child is dead
    if(waitpid($self->ChildPid, WNOHANG) != 0) {
      $killedChild = 1;
      last;
    }
    sleep(1);
  }

  $self->KillChild if(!$killedChild);
  $self->ShutdownHandler;

  ($SIG{'TERM'}, $SIG{'INT'}) = ($osigTerm, $osigInt);

#  $self->PrintLine('[*] Exiting ' . $self->SelfName . ' Handler...');
}

sub SetupHandler {
  my $self = shift;
#  $self->PrintLine('Hit default SetupHandler.');
}

sub ShutdownHandler {
	my $self = shift;
	$self->PipeClose($self->PipeRemoteIn);
	$self->PipeClose($self->PipeRemoteOut);
}

sub CheckHandler {
  my $self = shift;
#  $self->PrintLine('Hit default CheckHandler.');
  return(0);
}

sub KillChild {
  my $self = shift;
  kill('KILL', $self->{'ChildPid'});
  $self->PrintDebugLine(3, 'Killing child: ' . $self->{'ChildPid'});
}

sub ChildHandler {
  my $self = shift;
  my $sock = shift;
  sleep(1);
  return;
}

sub SigHandler {
  my $self = shift;
  $self->StopHandling(1);
}

sub HandleConnection {
  my $self = shift;
}

#
# Gives the check loop time to receive a connection
#
sub ExtraDelay
{
	my $self = shift;

	sleep(1);
}

1;
