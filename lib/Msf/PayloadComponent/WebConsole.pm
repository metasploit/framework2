#!/usr/bin/perl

package Msf::PayloadComponent::WebConsole;
use strict;
use IO::Handle;
use IO::Select;
use base 'Msf::PayloadComponents::TextConsole';
use vars qw{ @ISA };

sub import {
  my $class = shift;
  @ISA = ('Msf::Payload');
  foreach (@_) {
    eval("use $_");
    unshift(@ISA, $_);
  }
}

sub ConsoleIn {
    my $self = shift;
    return $self->GetVar('BROWSER') if $self->GetVar('BROWSER');
    return $self->SUPER::ConsoleIn;
}

sub ConsoleOut {
    my $self = shift;
    return $self->GetVar('BROWSER') if $self->GetVar('BROWSER');
    return $self->SUPER::ConsoleOut;
}

sub HandleConsole {
  my $self = shift;

  # Create listener socket
  my $psock = IO::Socket::INET->new
  (
    LocalAddr => '0.0.0.0',
    LocalPort => 0,
    ReuseAddr => 1,
    Listen    => 3,
  );
  
  if (! $psock) {
    print $self->ConsoleOut "WebConsole: HandleConsole(): Failed to bind a port for the proxy shell: $!\n";
    return;
  }
  
  # Display listener link to browser
  $psock->blocking(0);
  $psock->autoflush(1);
  
  # Close socket to browser
  # Accept connection from user
  # Map connected socket to ConsoleIn, ConsoleOut
  # Call upwards to TextConsole's HandleConsole


  $self->SUPER::HandleConsole;
}

1;
