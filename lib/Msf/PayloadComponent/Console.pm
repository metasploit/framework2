#!/usr/bin/perl

package Msf::PayloadComponent::Console;
use strict;
use IO::Handle;
use IO::Select;
use base 'Msf::Payload';
use vars qw{ @ISA };

sub _Import {
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
  __PACKAGE__->_Import($console);
  $self->_HandleConsole;
#  $self->SUPER::HandleConsole;
}


1;
