#!/usr/bin/perl

package Msf::PayloadComponent::Console;
use strict;
use base 'Msf::Payload';
use IO::Handle;
use IO::Select;

sub HandleConsole {
  my $self = shift;
  my $sockIn = $self->SocketIn;
  my $sockOut = $self->SocketOut;
  my $loop = 1;

  print "\n";

  my $sigHandler = sub {
    print "Caught ctrl-c, exit connection? [y/n] ";
    my $answer = <STDIN>;
    chomp($answer);
    if(lc($answer) eq 'y') {
      $loop = 0;
    }
  };

  my ($osigTerm, $osigInt) = ($SIG{'TERM'}, $SIG{'INT'});
  $SIG{'TERM'} = $sigHandler;
  $SIG{'INT'} = $sigHandler;

  my $stdin = IO::Handle->new_from_fd(0, '<');
  $sockIn->blocking(1);
  $sockIn->autoflush(1);
  $sockOut->blocking(1);
  $sockOut->autoflush(1);
  $stdin->blocking(1);
  $stdin->autoflush(1);

  my $selector = IO::Select->new($stdin, $sock);

LOOPER:
  while($loop) {
    my @ready = $selector->can_read;
    foreach my $ready (@ready) {
      if($ready == $stdin) {
        my $data = $self->SendFilter($stdin->getline);
        $sockOut->send($data);
      }
      elsif($ready == $sock) {
        my $data;
        $sockIn->recv($data, 4096);
        last LOOPER if(!length($data));
        print $self->RecvFilter($data);
      }
      else {
        print "Well thats a bug.\n";
      }
    }
  }

  ($SIG{'TERM'}, $SIG{'INT'}) = ($osigTerm, $osigInt);
}

sub SendFilter {
  my $self = shift;
  my $data = shift;
  return($data);
}

sub RecvFilter {
  my $self = shift;
  my $data = shift;
  return($data);
}

1;
