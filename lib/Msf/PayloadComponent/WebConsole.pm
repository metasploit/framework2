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

sub HandleConsole {
  my $self = shift;

  # Create listener socket
  # Display listener link to browser
  # Close socket to browser
  # Accept connection from user
  # Map connected socket to ConsoleIn, ConsoleOut
  # Call upwards to TextConsole's HandleConsole


  $self->SUPER::HandleConsole;
}

1;
