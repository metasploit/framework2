package Msf::PayloadComponent::Win32StagePayload;
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

sub Win32StagePayload {
  my $self = shift;
  return($self->_Info->{'Win32StagePayload'});
}

sub HandleConnection {
  my $self = shift;
  $self->SUPER::HandleConnection;
  my $sock = $self->SocketOut;
  my $blocking = $sock->blocking;
  $sock->blocking(1);

  my $payload = $self->BuildWin32($self->Win32StagePayload);

  $self->PrintLine('[*] Sending Stage (' . length($payload) . ' bytes)');
  $sock->send($payload);
  $self->PrintDebugLine(3, '[*] Stage Sent.');

  $sock->blocking($blocking);


}

1;
