#!/usr/bin/perl

package Msf::PayloadComponent::Console;
use strict;
use IO::Handle;
use IO::Select;
use base 'Msf::Payload';
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
  my $console = $self->GetVar('_Console');
  $console = 'Msf::PayloadComponent::TextConsole' if(!$console);
  __PACKAGE__->import($console);
  $self->_HandleConsole;
#  $self->SUPER::HandleConsole;
}


1;
