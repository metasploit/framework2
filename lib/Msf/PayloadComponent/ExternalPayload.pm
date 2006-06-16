
###############

##
#         Name: ExternalPayload.pm
#       Author: spoonm <ninjatools [at] hush.com>
#      Version: $Revision$
#  Description: Parent class for External Payloads.
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Msf::PayloadComponent::ExternalPayload;
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

sub Build {
  my $self = shift;
  my $opts = { };
  foreach (keys(%{$self->UserOpts})) {
    $opts->{$_} = $self->GetVar($_);
  }
  return($self->Generate($opts));
}

sub Generate {
  my $self = shift;
  my $opts = shift;
  my $prog = $self->{'Filename'};
  my @args;
  
  foreach (keys(%{$opts})) {
    push @args, $_.'='.$opts->{$_};
  }
  
  if(! -e $prog)  {
    $self->SetError("Program $prog does not exist");
    return;
  }

  $self->PrintDebugLine(3, "Running: $prog ".join(" ",@args));

  local *PROG;
  local $/;
  
  if(! open(PROG, "-|"))
  {
      exec($prog, @args);
      exit(0);
  }

  my $data = <PROG>;
  close(PROG);
  
  if (! $data)
  {
    $self->SetError("Payload creation failed");
    return;  
  }
  
  return($data);
}

1;
